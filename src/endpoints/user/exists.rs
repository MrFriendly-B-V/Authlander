use std::sync::Arc;
use actix_web::{web, get, HttpResponse};
use mysql::prelude::Queryable;
use mysql::{Row, params};
use crate::env::AppData;
use crate::error::HttpResult;
use serde::Serialize;

#[derive(Serialize)]
struct Response {
    exists: bool
}

#[get("/user/exists/{user_id}")]
pub async fn exists(data: web::Data<Arc<AppData>>, web::Path(user_id): web::Path<String>) -> HttpResult {
    let mut conn = data.pool.get_conn()?;
    let row: Option<Row> = conn.exec_first("SELECT 1 FROM users WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    })?;

    Ok(HttpResponse::Ok().json(&Response { exists: row.is_some() }))
}