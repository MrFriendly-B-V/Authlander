use actix_web::{get, web, HttpResponse};
use common_components::{AppData, respond};
use crate::{env::Env, ExtraData};
use super::SessionError;
use serde::Serialize;
use mysql::{prelude::Queryable, Row, Params, params};
use log::warn;

#[derive(Serialize)]
struct CheckResponse {
    session_valid:  bool,
    active:         bool
}

#[get("/session/check/{session_id}")]
pub async fn check(data: web::Data<AppData<Env, ExtraData>>, web::Path(session_id): web::Path<String>) -> HttpResponse {
    if session_id.is_empty() {
        return HttpResponse::BadRequest().body(respond!("path", "Missing session_id"));
    }

    match super::check_session(&data, &session_id) {
        Ok(_) => {},
        Err(e) => {
            return match e {
                SessionError::InternalError => HttpResponse::InternalServerError().body(respond!("internal", "Internal error")),
                SessionError::NotFound => HttpResponse::Unauthorized().body(respond!("session_id", "Session does not exist")),
                SessionError::Expired => HttpResponse::Unauthorized().body(respond!("session_id", "Session has expired"))
            };
        }
    }

    let mut conn = match data.get_conn() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create MySQL connection in GET /session/describe/: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    let user_id: String = match conn.exec_first::<Row, &str, Params>("SELECT user_id FROM sessions WHERE session_id = :session_id", params! {
        "session_id" => &session_id
    }) {
        Ok(Some(row)) => {
            row.get("user_id").unwrap()
        },
        Ok(None) => unreachable!(), //Checked by the check_session call above,
        Err(e) => {
            warn!("Failed to query table 'sessions' in GET /session/describe/: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    match conn.exec_first::<Row, &str, Params>("SELECT active FROM users WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    }) {
        Ok(Some(row)) => {
            let active: bool = row.get("active").unwrap();

            if !active {
                HttpResponse::Ok().content_type("application/json").body(respond!(CheckResponse { active: false, session_valid: false }))
            } else {
                HttpResponse::Ok().content_type("application/json").body(respond!(CheckResponse { active: true, session_valid: true }))
            }
        },
        Ok(None) => {
            warn!("Found stray session '{}' for nonexistent user '{}'!", &session_id, &user_id);
            match conn.exec_drop("DELETE FROM sessions WHERE session_id = :session_id", params! {
                "session_id" => &session_id
            }) {
                Ok(_) => {},
                Err(e) => {
                    warn!("Failed to delete stray session from table 'sessionns' for GET /session/describe/: {:?}", e);
                    return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"))
                }
            }

            HttpResponse::Conflict().body(respond!("user_id", "No user exists for provided session_id, but session exists."))
        },
        Err(e) => {
            warn!("Failed to query table 'users' in GET /session/describe/: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    }
}