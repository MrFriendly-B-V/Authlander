use std::sync::Arc;
use actix_web::{get, web, HttpResponse};
use crate::env::AppData;
use crate::error::{Error, HttpResult};
use serde::Serialize;
use mysql::{prelude::Queryable, Row, Params, params};
use log::warn;

#[derive(Serialize)]
struct CheckResponse {
    session_valid:  bool,
    active:         bool
}

#[get("/session/check/{session_id}")]
pub async fn check(data: web::Data<Arc<AppData>>, web::Path(session_id): web::Path<String>) -> HttpResult {
    super::check_session(&data, &session_id)?;

    let mut conn = data.pool.get_conn()?;

    let user_id: String = match conn.exec_first::<Row, &str, Params>("SELECT user_id FROM sessions WHERE session_id = :session_id", params! {
        "session_id" => &session_id
    })? {
        Some(row) => {
            row.get("user_id").unwrap()
        },
        None => unreachable!(), //Checked by the check_session call above,
    };

    match conn.exec_first::<Row, &str, Params>("SELECT active FROM users WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    })? {
        Some(row) => {
            let active: bool = row.get("active").unwrap();

            if !active {
                Ok(HttpResponse::Ok().json(&CheckResponse { active: false, session_valid: false }))
            } else {
                Ok(HttpResponse::Ok().json(&CheckResponse { active: true, session_valid: true }))
            }
        },
        None => {
            warn!("Found stray session '{}' for nonexistent user '{}'!", &session_id, &user_id);
            conn.exec_drop("DELETE FROM sessions WHERE session_id = :session_id", params! {
                "session_id" => &session_id
            })?;

            Err(Error::Conflict("No user exists for provided session_id, but session exists."))
        }
    }
}