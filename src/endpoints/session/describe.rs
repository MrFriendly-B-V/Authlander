use std::sync::Arc;
use actix_web::{get, web, HttpResponse};
use mysql::{prelude::Queryable, Row, Params, params};
use serde::Serialize;
use crate::env::AppData;
use crate::error::{HttpResult, Error};
use log::warn;

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
pub async fn describe(data: web::Data<Arc<AppData>>, web::Path(session_id): web::Path<String>) -> HttpResult {
    super::check_session(&data, &session_id)?;
    let mut conn = data.pool.get_conn()?;

    let row: Row = match conn.exec_first::<Row, &str, Params>("SELECT user_id,expiry FROM sessions WHERE session_id = :session_id", params! {
        "session_id" => &session_id
    })? {
        Some(r) => r,
        None => unreachable!(), // Unreachable, the call to super::check_session() above already checked if the session exists.
    };

    let user_id: String = row.get("user_id").unwrap();
    let expiry: i64 = row.get("expiry").unwrap();

    let row: Row = match conn.exec_first::<Row, &str, Params>("SELECT active,name,email,picture FROM users WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    })? {
        Some(r) => r,
        None => {
            warn!("Found stray session '{}' for nonexistent user '{}'!", &session_id, &user_id);
            conn.exec_drop("DELETE FROM sessions WHERE session_id = :session_id", params! {
                "session_id" => &session_id
            })?;

            return Err(Error::Conflict("No user exists for provided session_id, but session exists."));
        }
    };

    let active: bool = row.get("active").unwrap();
    if !active {
        return Ok(HttpResponse::Ok().json(&DescribeResponse { active: false, user_id: None, expiry: None, name: None, picture: None, email: None }));
    }

    let name: Option<String> = row.get("name").unwrap();
    let email: Option<String> = row.get("email").unwrap();
    let picture: Option<String> = row.get("picture").unwrap();

    let payload = DescribeResponse {
        active:     true,
        user_id:    Some(user_id),
        expiry:     Some(expiry),
        name,
        picture,
        email
    };

    Ok(HttpResponse::Ok().json(&payload))
}