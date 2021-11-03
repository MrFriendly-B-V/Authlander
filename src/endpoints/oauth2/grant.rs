use std::sync::Arc;
use actix_web::{get, web, HttpResponse};
use mysql::{prelude::Queryable, Row, Params, params};
use crate::env::AppData;
use crate::error::{Error, HttpResult};
use serde::Deserialize;
use rand::Rng;

#[derive(Deserialize)]
pub struct GrantQuery {
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
pub async fn grant(data: web::Data<Arc<AppData>>, query: web::Query<GrantQuery>) -> HttpResult {
    let mut conn = data.pool.get_conn()?;

    // Check if we got a code or an error
    match (&query.code, &query.error) {
        (Some(code), None) => {
            // We got a code, good. Query the database for the data associated with the state we got
            let state_row: Row = match conn.exec_first("SELECT nonce,redirect_uri FROM states WHERE state = :state", params! {
                "state" => &query.state
            })? {
                Some(ru) => ru,
                None => return Err(Error::NotFound("Provided parameter 'state' does not exist.")),
            };

            let nonce: String = state_row.get("nonce").unwrap();
            let redirect_uri_base64: String = state_row.get("redirect_uri").unwrap();

            // Exchange the grant token (i.e code) for a refresh- & ID token
            let exchange_response = crate::apis::google_auth::exchange_grant_token(&data.env, &code, &format!("{}/oauth2/grant", &data.env.host))?;

            // The ID token is a JWT, which have the format xx.yy.zz, where
            // x: The header
            // y: The payload
            // z: The signature
            // As per Google docs we do not have to verify the signature here, we can assume it is trusted
            // This means we don't need the header either, leaving us the payload.
            let jwt_parts = exchange_response.id_token.split(".").collect::<Vec<&str>>();
            let jwt_payload_base64 = jwt_parts.get(1).unwrap();

            // The payload is encoded as base64, convert this to a UTF-8 JSON string
            let jwt = base64::decode(jwt_payload_base64)?;
            let jwt_payload = String::from_utf8(jwt)?;

            // Lastly, deserialize the String
            let jwt_payload: JwtPayload = serde_json::from_str(&jwt_payload)?;

            // We must verify the nonce we gave in the original GET /login with the nonce contained in the ID token
            // If it is not equal, drop the state record and return a 401.
            //TODO Would a different status code be more appropriate here?
            if jwt_payload.nonce.ne(&nonce) {
                conn.exec_drop("DELETE FROM states WHERE state = :state", params! {
                    "state" => &query.state
                })?;

                return Err(Error::Unauthorized)
            }

            let row: Option<Row> = conn.exec_first::<Row, &str, Params>("SELECT refresh_token,name,email,picture FROM users WHERE user_id = :sub", params! {
                "sub" => &jwt_payload.sub
            })?;

            // Check if the database already has a record of our user
            // If it does, check for the selected fields if they are up-to-date with the newly provided data
            // If it does not, insert a new row with the data that we have.
            match row {
                Some(r) => {
                    // We know now that the record already exists

                    // Check the refresh token, and update if necessary
                    if let Some(refresh_token) = exchange_response.refresh_token {
                        let existing_refresh_token: String = r.get("refresh_token").unwrap();
                        if refresh_token.ne(&existing_refresh_token) {
                            conn.exec_drop("UPDATE users SET refresh_token = :refresh_token WHERE user_id = :sub", params! {
                                "refresh_token" => &refresh_token,
                                "sub" => &jwt_payload.sub
                            })?;
                        }
                    }

                    // Check the email, and update if necessary
                    let existing_email: String = r.get("email").unwrap();
                    if jwt_payload.email.ne(&existing_email) {
                        conn.exec_drop("UPDATE users SET email = :email WHERE user_id = :sub", params! {
                            "email" => &jwt_payload.email,
                            "sub" => &jwt_payload.sub
                        })?;
                    }

                    // Check the name, and update if necessary
                    if let Some(name) = jwt_payload.name {
                        let existing_name: String = r.get("name").unwrap();
                        if name.ne(&existing_name) {
                            conn.exec_drop("UPDATE users SET name = :name WHERE user_id = :sub", params! {
                                "name" => &name,
                                "sub" => &jwt_payload.sub
                            })?;
                        }
                    }

                    // Check the picture, and update if necessary
                    if let Some(picture) = jwt_payload.picture {
                        let exiting_picture: String = r.get("picture").unwrap();
                        if picture.ne(&exiting_picture) {
                            conn.exec_drop("UPDATE users SET picture = :picture WHERE user_id = :sub", params! {
                                "picture" => &picture,
                                "sub" => &jwt_payload.sub
                            })?;
                        }
                    }
                },
                None => {
                    // No record of the user exists yet
                    conn.exec_drop("INSERT INTO users (user_id, active, name, email, picture, refresh_token) VALUES (:user_id, true, :name, :email, :picture, :refresh_token)", params! {
                        "user_id" => &jwt_payload.sub,
                        "name" => &jwt_payload.name,
                        "email" => &jwt_payload.email,
                        "picture" => &jwt_payload.picture,
                        "refresh_token" => &exchange_response.refresh_token
                    })?
                }
            }

            // We can now be sure a record exists for the user, and that it is as up to date as Google wants it to be
            // Create a new session for the user
            let session_id: String = rand::thread_rng().sample_iter(rand::distributions::Alphanumeric).take(32).map(char::from).collect();
            let expiry = chrono::Utc::now().timestamp() + SESSION_EXPIRY_TIME_SECS as i64;

            // Inser the new session into the database
            conn.exec_drop("INSERT INTO sessions (session_id, user_id, expiry) VALUES (:session_id, :user_id, :expiry)", params! {
                "session_id" => &session_id,
                "user_id" => &jwt_payload.sub,
                "expiry" => &expiry
            })?;

            // Delete the state record, it is no longer relevant
            conn.exec_drop("DELETE FROM states WHERE state = :state", params! {
                "state" => &query.state
            })?;

            // The redirect stored in the database is base64, decode it to a UTF-8 String
            let redirect_uri = base64::decode(&redirect_uri_base64)?;
            let redirect_uri = String::from_utf8(redirect_uri)?;

            // Append the generated session ID to the redirect uri provided in GET /login
            let redirect_uri = if redirect_uri.contains("?") {
                format!("{}&session_id={}", &redirect_uri, session_id)
            } else {
                format!("{}?session_id={}", &redirect_uri, session_id)
            };

            let mut ctx = tera::Context::new();
            ctx.insert("redirect_uri", &redirect_uri);

            // Finally, put the redirect uri in the redirect template and return that as body
            let body = data.tera.render("redirect.html", &ctx)?;
            return Ok(HttpResponse::Ok().body(&body));
        },
        (None, Some(error)) => {
            // We did not get a code, but rather an error
            // We can immediately drop the state, as it's no longer relevant
            conn.exec_drop("DELETE FROM states WHERE state = :state", params! {
                "state" => &query.state
            })?;

            // We want to tailor our response code to the error we got
            match error.as_str() {
                "access_denied" => Err(Error::UnauthorizedMsg("The user did not grant Authlander access")),
                "admin_policy_enforced" | "org_internal" => Err(Error::UnauthorizedMsg("The user is not part of the organization owning this OAuth2 client, or admin policies prevent the user from granting access.")),
                "disallowed_useragent" => Err(Error::UnauthorizedMsg("The user uses a User-Agent dissalowed by Google.")),
                "redirect_uri_mismatch" => Err(Error::Unauthorized),
                _ => Err(Error::BadRequest("Received invalid error code from Google"))
            }
        },
        _ => Err(Error::BadRequest("Expected either an 'error' or a 'code', neither were provided."))
    }
}