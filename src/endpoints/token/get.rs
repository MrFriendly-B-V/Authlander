use std::sync::Arc;
use actix_web::{get, web, HttpRequest, HttpResponse};
use mysql::{Row, params};
use mysql::prelude::Queryable;
use serde::Serialize;
use crate::env::AppData;
use crate::error::{Error, HttpResult};
use crate::check_token;
use log::warn;

#[derive(Serialize)]
struct TokenResponse<'a> {
    access_token: Option<&'a str>,
    expiry:       Option<i64>,
    active:       bool
}

#[get("/token/get/{user_id}")]
pub async fn get(data: web::Data<Arc<AppData>>, req: HttpRequest, web::Path(user_id): web::Path<String>) -> HttpResult {
    check_token!(req, data);
    let mut conn = data.pool.get_conn()?;

    let refresh_token: Row = match conn.exec_first("SELECT refresh_token FROM users WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    })? {
        Some(r) => r,
        None => return Err(Error::NotFound("The requested user does not exist")),
    };

    let refresh_token = match refresh_token.get::<Option<String>, &str>("refresh_token").unwrap() {
        Some(rt) => rt,
        None => {
            warn!("Found user '{}' without refresh_token!", &user_id);
            conn.exec_drop("UPDATE users SET active = false WHERE user_id = :user_id", params! {
                "user_id" => &user_id
            })?;

            return Err(Error::Conflict("Internal conflict"));
        }
    };

    let refresh_response = crate::apis::google_auth::refresh_token(&data.env, &refresh_token)?;

    let response = TokenResponse {
        access_token:   Some(&refresh_response.access_token),
        expiry:         Some(chrono::Utc::now().timestamp() + refresh_response.expires_in),
        active:         true
    };

    Ok(HttpResponse::Ok().json(&response))
}