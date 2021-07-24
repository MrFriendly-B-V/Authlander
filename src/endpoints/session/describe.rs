use actix_web::{get, web, HttpResponse};
use mysql::{prelude::Queryable, Row, Params, params};
use serde::Serialize;
use common_components::{AppData, respond};
use crate::{env::Env, ExtraData};
use log::warn;
use super::SessionError;

#[derive(Serialize)]
struct DescribeResponse {
    active:     bool,
    user_id:    Option<String>,
    expiry:     Option<i64>,
    name:       Option<String>,
    picture:    Option<String>,
    email:      Option<String>,
}

#[get("/session/describe/{session_id}")]
pub async fn describe(data: web::Data<AppData<Env, ExtraData>>, web::Path(session_id): web::Path<String>) -> HttpResponse {
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
            }
        }
    }

    let mut conn = match data.get_conn() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create MySQL connection in GET /session/describe/: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    let (user_id, expiry) = match conn.exec_first::<Row, &str, Params>("SELECT user_id,expiry FROM sessions WHERE session_id = :session_id", params! {
        "session_id" => &session_id
    }) {
        Ok(Some(session_row)) => {
            let user_id: String = session_row.get("user_id").unwrap();
            let expiry: i64 = session_row.get("expiry").unwrap();
            (user_id, expiry)
        },
        Ok(None) => unreachable!(), // Unreachable, the call to super::check_session() above already checked if the session exists.
        Err(e) => {
            warn!("Failed to query table 'sessions' in GET /session/describe/: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"))
        }
    };

    let (name, email, picture) = match conn.exec_first::<Row, &str, Params>("SELECT active,name,email,picture FROM users WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    }) {
        Ok(Some(row)) => {
            let active: bool = row.get("active").unwrap();
            if !active {
                return HttpResponse::Ok().content_type("application/json").body(respond!(DescribeResponse { active: false, user_id: None, expiry: None, name: None, picture: None, email: None }))
            }

            let name: Option<String> = row.get("name").unwrap();
            let email: Option<String> = row.get("email").unwrap();
            let picture: Option<String> = row.get("picture").unwrap();

            (name, email, picture)
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

            return HttpResponse::Conflict().body(respond!("user_id", "No user exists for provided session_id, but session exists."));
        },
        Err(e) => {
            warn!("Failed to query table 'users' for GET /session/describe: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    HttpResponse::Ok().content_type("application/json").body(respond!(DescribeResponse {
        active:     true,
        user_id:    Some(user_id),
        expiry:     Some(expiry),
        name,
        picture,
        email
    }))
}