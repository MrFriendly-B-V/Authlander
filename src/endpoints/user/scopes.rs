use std::sync::Arc;
use actix_web::{get, web, HttpResponse};
use mysql::{Row, params};
use mysql::prelude::Queryable;
use serde::Serialize;
use crate::env::AppData;
use crate::error::{Error, HttpResult};

#[derive(Serialize)]
struct ScopesResponse {
    scopes:     Vec<String>,
    is_active:  bool
}

#[get("/user/scopes/{user_id}")]
pub async fn scopes(data: web::Data<Arc<AppData>>, web::Path(user_id): web::Path<String>) -> HttpResult {
    let mut conn = data.pool.get_conn()?;

    let row: Row = match conn.exec_first("SELECT active FROM users WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    })? {
        Some(r) => r,
        None => return Err(Error::NotFound("The requested user does not exist")),
    };

    let active: bool = row.get("active").unwrap();

    if !active {
        return Ok(HttpResponse::Ok().json(&ScopesResponse { scopes: vec![], is_active: false }));
    }

    let scopes = crate::endpoints::get_scopes(&data, &user_id)?;

    Ok(HttpResponse::Ok().json(&ScopesResponse { scopes, is_active: true}))
}
