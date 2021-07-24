use actix_web::{get, web, HttpRequest, HttpResponse};
use mysql::{prelude::Queryable, Row, Params, params};
use common_components::{AppData, respond};
use crate::{env::Env, ExtraData};
use serde::Deserialize;
use log::warn;
use rand::Rng;

#[derive(Deserialize)]
struct GrantQuery {
    error:  Option<String>,
    code:   Option<String>,
    state:  String,
}

#[derive(Deserialize)]
struct JwtPayload {
    sub:        String,
    name:       Option<String>,
    email:      String,
    picture:    Option<String>,
    nonce:      String,
}

// 1 day
const SESSION_EXPIRY_TIME_SECS: u64 = 86_400;

#[get("/oauth2/grant")]
pub async fn grant(data: web::Data<AppData<Env, ExtraData>>, req: HttpRequest) -> HttpResponse {
    let grant_query: GrantQuery = match serde_qs::from_str(req.query_string()) {
        Ok(gq) => gq,
        Err(e) => {
            warn!("Failed to parse query parameters for GET /oauth2/grant: {:?}", e);
            return HttpResponse::BadRequest().body(respond!("query", format!("{:?}", &e)))
        }
    };

    let mut conn = match data.get_conn() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create MySQL Connection for GET /oauth2/grant: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    // Check if we got a code or an error
    match (grant_query.code, grant_query.error) {
        (Some(code), None) => {
            // We got a code, good. Query the database for the data associated with the state we got
            let state_row: Row = match conn.exec_first("SELECT nonce,redirect_uri FROM states WHERE state = :state", params! {
                "state" => &grant_query.state
            }) {
                Ok(Some(ru)) => ru,
                Ok(None) => return HttpResponse::Conflict().body(respond!("query", "Provided parameter 'state' does not exist.")),
                Err(e) => {
                    warn!("Failed to query table 'states' for GET /oauth2/grant: {:?}", e);
                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                }
            };

            let nonce: String = state_row.get("nonce").unwrap();
            let redirect_uri_base64: String = state_row.get("redirect_uri").unwrap();

            // Exchange the grant token (i.e code) for a refresh- & ID token
            let exchange_response = match crate::apis::google_auth::exchange_grant_token(&data.env, &code, &format!("{}/oauth2/grant", &data.env.host)) {
                Ok(er) => er,
                Err(e) => {
                    warn!("Failed to exchange grant token for access token in GET /oauth2/grant: {}", e);
                    return HttpResponse::InternalServerError().body(respond!("external", "External API error"));
                }
            };

            // The ID token is a JWT, which have the format xx.yy.zz, where
            // x: The header
            // y: The payload
            // z: The signature
            // As per Google docs we do not have to verify the signature here, we can assume it is trusted
            // This means we don't need the header either, leaving us the payload.
            let jwt_parts = exchange_response.id_token.split(".").collect::<Vec<&str>>();
            let jwt_payload_base64 = jwt_parts.get(1).unwrap();

            // The payload is encoded as base64, convert this to a UTF-8 JSON string
            let jwt_payload = match base64::decode(jwt_payload_base64) {
                Ok(jwt_payload_decoded_bytes) => match String::from_utf8(jwt_payload_decoded_bytes) {
                    Ok(jwt_payload) => jwt_payload,
                    Err(e) => {
                        warn!("Failed to convert decoded JWT bvtes to a UTF-8 String in GET /oauth2/grant: {:?}", e);
                        return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                    }
                },
                Err(e) => {
                    warn!("Failed to decode JWT payload from Base64 in GET /oauth2/grant: {:?}", e);
                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                }
            };

            // Lastly, deserialize the String
            let jwt_payload: JwtPayload = match serde_json::from_str(&jwt_payload) {
                Ok(jp) => jp,
                Err(e) => {
                    warn!("Failed to deserialize Google OpenID JWT Payload: {:?}", e);
                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                }
            };

            // We must verify the nonce we gave in the original GET /login with the nonce contained in the ID token
            // If it is not equal, drop the state record and return a 401.
            //TODO Would a different status code be more appropriate here?
            if jwt_payload.nonce.ne(&nonce) {
                match conn.exec_drop("DELETE FROM states WHERE state = :state", params! {
                    "state" => &grant_query.state
                }) {
                    Ok(_) => {},
                    Err(e) => {
                        warn!("Failed to delete from table 'states' for non-equal 'nonce' in GET /oauth2/grant: {:?}", e);
                        return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                    }
                }

                return HttpResponse::Unauthorized().body(respond!("state", "Nonce associated with state is invalid."));
            }

            // Check if the database already has a record of our user
            // If it does, check for the selected fields if they are up-to-date with the newly provided data
            // If it does not, insert a new row with the data that we have.
            match conn.exec_first::<Row, &str, Params>("SELECT refresh_token,name,email,picture FROM users WHERE user_id = :sub", params! {
                "sub" => &jwt_payload.sub
            }) {
                Ok(Some(user_row)) => {
                    // We know now that the record already exists

                    // Check the refresh token, and update if necessary
                    if let Some(refresh_token) = exchange_response.refresh_token {
                        let existing_refresh_token: String = user_row.get("refresh_token").unwrap();
                        if refresh_token.ne(&existing_refresh_token) {
                            match conn.exec_drop("UPDATE users SET refresh_token = :refresh_token WHERE user_id = :sub", params! {
                            "refresh_token" => &refresh_token,
                            "sub" => &jwt_payload.sub
                        }) {
                                Ok(_) => {},
                                Err(e) => {
                                    warn!("Failed to update Refresh token in table 'users' for GET /oauth2/grant: {:?}", e);
                                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                                }
                            }
                        }
                    }

                    // Check the email, and update if necessary
                    let existing_email: String = user_row.get("email").unwrap();
                    if jwt_payload.email.ne(&existing_email) {
                        match conn.exec_drop("UPDATE users SET email = :email WHERE user_id = :sub", params! {
                            "email" => &jwt_payload.email,
                            "sub" => &jwt_payload.sub
                        }) {
                            Ok(_) => {},
                            Err(e) => {
                                warn!("Failed to update email in table 'users' for GET /oauth2/grant: {:?}", e);
                                return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                            }
                        }
                    }

                    // Check the name, and update if necessary
                    if let Some(name) = jwt_payload.name {
                        let existing_name: String = user_row.get("name").unwrap();
                        if name.ne(&existing_name) {
                            match conn.exec_drop("UPDATE users SET name = :name WHERE user_id = :sub", params! {
                            "name" => &name,
                            "sub" => &jwt_payload.sub
                        }) {
                                Ok(_) => {},
                                Err(e) => {
                                    warn!("Failed to update name in table 'users' for GET /oauth2/grant: {:?}", e);
                                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                                }
                            }
                        }
                    }

                    // Check the picture, and update if necessary
                    if let Some(picture) = jwt_payload.picture {
                        let exiting_picture: String = user_row.get("picture").unwrap();
                        if picture.ne(&exiting_picture) {
                            match conn.exec_drop("UPDATE users SET picture = :picture WHERE user_id = :sub", params! {
                            "picture" => &picture,
                            "sub" => &jwt_payload.sub
                        }) {
                                Ok(_) => {},
                                Err(e) => {
                                    warn!("Failed to update picture in table 'users' for GET /oauth2/grant: {:?}", e);
                                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                                }
                            }
                        }
                    }
                }
                Ok(None) =>  {
                    // No record of the user exists yet
                    match conn.exec_drop("INSERT INTO users (user_id, active, name, email, picture, refresh_token) VALUES (:user_id, true, :name, :email, :picture, :refresh_token)", params! {
                        "user_id" => &jwt_payload.sub,
                        "name" => &jwt_payload.name,
                        "email" => &jwt_payload.email,
                        "picture" => &jwt_payload.picture,
                        "refresh_token" => &exchange_response.refresh_token
                    }) {
                        Ok(_) => {},
                        Err(e) => {
                            warn!("Failed to insert new user into table 'users' for GET /oauth2/grant: {:?}", e);
                            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to query 'users' table for an existing record for GET /oauth2/grant: {:?}", e);
                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                }
            }

            // We can now be sure a record exists for the user, and that it is as up to date as Google wants it to be
            // Create a new session for the user
            let session_id: String = rand::thread_rng().sample_iter(rand::distributions::Alphanumeric).take(32).map(char::from).collect();
            let expiry = chrono::Utc::now().timestamp() + SESSION_EXPIRY_TIME_SECS as i64;

            // Inser the new session into the database
            match conn.exec_drop("INSERT INTO sessions (session_id, user_id, expiry) VALUES (:session_id, :user_id, :expiry)", params! {
                "session_id" => &session_id,
                "user_id" => &jwt_payload.sub,
                "expiry" => &expiry
            }) {
                Ok(_) => {},
                Err(e) => {
                    warn!("Failed to insert new session into 'sessions' table for GET /oauth2/grant: {:?}", e);
                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                }
            }

            // Delete the state record, it is no longer relevant
            match conn.exec_drop("DELETE FROM states WHERE state = :state", params! {
                    "state" => &grant_query.state
                }) {
                Ok(_) => {},
                Err(e) => {
                    warn!("Failed to delete from table 'states' for non-equal 'nonce' in GET /oauth2/grant: {:?}", e);
                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                }
            }

            // The redirect stored in the database is base64, decode it to a UTF-8 String
            let redirect_uri = match base64::decode(&redirect_uri_base64) {
                Ok(red_uri_bytes) => match String::from_utf8(red_uri_bytes) {
                    Ok(ru) => ru,
                    Err(e) => {
                        warn!("Failed to create UTF-8 String from redirect URI in GET /oauth2/grant: {:?}", &e);
                        return HttpResponse::BadRequest().body(respond!("query", format!("Redirect URI provided in GET /login is not valid UTF-8: {:?}", &e)));
                    }
                },
                Err(e) => {
                    warn!("Failed to convert redirect_uri from Base64 to Vec<u8> in GET/oauth2/grant: {:?}", &e);
                    return HttpResponse::BadRequest().body(respond!("query", format!("Redirect URI provided in GET /login is not valid Base64: {:?}", &e)));
                }
            };

            // Append the generated session ID to the redirect uri provided in GET /login
            let redirect_uri = if redirect_uri.contains("?") {
                format!("{}&session_id={}", &redirect_uri, session_id)
            } else {
                format!("{}?session_id={}", &redirect_uri, session_id)
            };

            let mut ctx = tera::Context::new();
            ctx.insert("redirect_uri", &redirect_uri);

            // Finally, put the redirect uri in the redirect template and return that as body
            let body = match data.extra.as_ref().unwrap().tera.render("redirect.html", &ctx) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to render Tera template 'redirect.html' in GET /oauth2/grant: {:?}", e);
                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                }
            };

            return HttpResponse::Ok().body(&body);
        },
        (None, Some(error)) => {
            // We did not get a code, but rather an error
            // We can immediately drop the state, as it's no longer relevant
            match conn.exec_drop("DELETE FROM states WHERE state = :state", params! {
                        "state" => &grant_query.state
                    }) {
                Ok(_) => {},
                Err(e) => {
                    warn!("Failed to delete state from table 'states' for GET /oauth2/grant: {:?}", e);
                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                }
            }

            // We want to tailor our response code to the error we got
            match error.as_str() {
                "access_denied" => HttpResponse::Unauthorized().body(respond!("user", "The user did not grant accesss.")),
                "admin_policy_enforced" | "org_internal" => HttpResponse::Unauthorized().body(respond!("organization", "The user is not part of the organization owning this OAuth2 client, or admin policies prevent the user from granting access.")),
                "disallowed_useragent" => HttpResponse::Unauthorized().body(respond!("useragent", "The user uses a User-Agent dissalowed by Google.")),
                "redirect_uri_mismatch" => HttpResponse::Unauthorized().body(respond!("configuration", "Invalid redirect URI")),
                _ => HttpResponse::BadRequest().body(respond!("query", "Invalid error"))
            }
        },
        _ => HttpResponse::BadRequest().body(respond!("query", "Expected either an 'error' or a 'code', neither were provided."))
    }
}