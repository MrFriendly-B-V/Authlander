use std::sync::Arc;
use actix_web::{web, get, HttpResponse, HttpRequest};
use mysql::prelude::Queryable;
use mysql::{Row, params, PooledConn};
use crate::env::AppData;
use crate::error::{HttpResult, Error};
use crate::check_token;
use serde::Serialize;

#[derive(Serialize)]
struct Response {
    users:  Vec<User>,
}

#[derive(Serialize)]
struct User {
    id:     String,
    name:   String,
    email:  String,
}

#[get("/user/list")]
pub async fn list(data: web::Data<Arc<AppData>>, req: HttpRequest) -> HttpResult {
    check_token!(req, data);
    let mut conn = data.pool.get_conn()?;
    let users = get_users(&mut conn)?;
    let response = Response {
        users
    };

    Ok(HttpResponse::Ok().json(&response))
}

fn get_users(conn: &mut PooledConn) -> Result<Vec<User>, Error> {
    let rows: Vec<Row> = conn.exec("SELECT user_id,name,email FROM users", Params::Empty)?;
    let users: Vec<_> = rows.into_iter()
        .map(|f| {
            User {
                id: f.get("user_id").unwrap(),
                name: f.get("name").unwrap(),
                email: f.get("email").unwrap()
            }
        })
        .collect();

    Ok(users)
}