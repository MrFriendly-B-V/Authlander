use actix_web::{get, web, HttpRequest, HttpResponse};
use mysql::{prelude::Queryable, Row, Params, params};
use serde::Serialize;
use common_components::{AppData, respond, ErrorKind};
use crate::{env::Env, ExtraData};
use log::warn;

#[derive(Serialize)]
struct TokenResponse<'a> {
    access_token: Option<&'a str>,
    expiry:       Option<i64>,
    active:       bool
}

#[get("/token/get/{user_id}")]
pub async fn get(data: web::Data<AppData<Env, ExtraData>>, req: HttpRequest, web::Path(user_id): web::Path<String>) -> HttpResponse {
    let access_token: String = match req.headers().get("authorization") {
        Some(at) => match at.to_str() {
            Ok(at) => at.to_string(),
            Err(e) => {
                warn!("Failed to convert header value of header 'Authorization' to &str in GET /token/get/: {:?}", e);
                return HttpResponse::BadRequest().body(respond!("headers", format!("Invalid value for header 'Authorization': {:?}", e)));
            }
        },
        None => {
            return HttpResponse::Unauthorized().body(respond!("headers", "Missing required header 'Authorization'"));
        }
    };

    match super::validate_access_token(&data, &access_token) {
        Ok(true) => {},
        Ok(false) => return HttpResponse::Unauthorized().body(respond!("headers", "Provided access token is not authorized")),
        Err(e) => {
            warn!("Failed to validate access token in GET /token/get: {}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    }

    let mut conn = match data.get_conn() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create MySQL connection in GET /token/get: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    let refresh_token = match conn.exec_first::<Row, &str, Params>("SELECT refresh_token FROM users WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    }) {
        Ok(Some(row)) => match row.get::<Option<String>, &str>("refresh_token").unwrap() {
            Some(rt) => rt,
            None => {
                warn!("Found user '{}' without refresh_token!", &user_id);
                match conn.exec_drop("UPDATE users SET active = false WHERE user_id = :user_id", params! {
                    "user_id" => &user_id
                }) {
                    Ok(_) => {},
                    Err(e) => {
                        warn!("Failed to update table 'users' in GET /token/get/: {:?}", e);
                        return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                    }
                }

                return HttpResponse::Ok().content_type("application/json").body(respond!(TokenResponse { expiry: None, access_token: None, active: false }))
            }
        },
        Ok(None ) => return HttpResponse::NotFound().body(respond!("user_id", "No user exists for the provided user_id")),
        Err(e) => {
            warn!("Failed to query table 'users' for refresh_token in GET /token/get/: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    let refresh_response = match crate::apis::google_auth::refresh_token(&data.env, &refresh_token) {
        Ok(rr) => rr,
        Err(e) => {
            match &e.kind {
                ErrorKind::Req(e) => {
                    // The return status is 401 or 403 when the user revoked Authlander's access to their account,
                    // As a result we want to invalidate all sessions and delete them from our user records.
                    if let Some(status) = e.status() {
                        if status.as_u16() == 401 || status.as_u16() == 403 {

                            //We do not delete from the scopes table, as the user just needs to log in again, and then their scopes are retained

                            match conn.exec_drop("DELETE FROM users WHERE user_id = :user_id", params! {
                            "user_id" => &user_id
                        }) {
                                Ok(_) => {},
                                Err(e) => {
                                    warn!("Failed to delete from table 'users' for user '{}' in GET /tokens/get: {:?}", &user_id, &e);
                                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                                }
                            }

                            match conn.exec_drop("DELETE FROM sessions WHERE user_id = :user_id", params! {
                            "user_id" => &user_id,
                        }) {
                                Ok(_) => {},
                                Err(e) => {
                                    warn!("Failed to delete from table 'sessions' for user '{}' in GET /tokens/get: {:?}", &user_id, &e);
                                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
                                }
                            }
                        }

                        return HttpResponse::Conflict().body(respond!("user", "User has revoked access"));
                    }
                },
                _ => {}
            }

            warn!("Failed to refresh token in GET /token/get/: {}", &e);
            return HttpResponse::InternalServerError().body(respond!("external", "External API error"));
        }
    };

    HttpResponse::Ok().content_type("application/json").body(respond!(TokenResponse {
        access_token:   Some(&refresh_response.access_token),
        expiry:         Some(chrono::Utc::now().timestamp() + refresh_response.expires_in),
        active:         true
    }))
}