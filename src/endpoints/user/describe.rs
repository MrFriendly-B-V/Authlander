use actix_web::{get, web, HttpRequest, HttpResponse};
use mysql::{prelude::Queryable, Row, Params, params};
use serde::Serialize;
use crate::env::AppData;
use std::sync::Arc;
use crate::error::{HttpResult, Error};

#[derive(Serialize)]
struct DescribeResponse {
    active:     bool,
    name:       Option<String>,
    email:      Option<String>,
    picture:    Option<String>,
}

#[get("/user/describe/{user_id}")]
pub async fn describe(data: web::Data<Arc<AppData>>, req: HttpRequest, web::Path(user_id): web::Path<String>) -> HttpResult {
    crate::check_token!(req, data);
    let mut conn = data.pool.get_conn()?;

    match conn.exec_first::<Row, &str, Params>("SELECT active,name,email,picture FROM users WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    })? {
        Some(row) => {
            let active: bool = row.get("active").unwrap();
            if !active {
                return Ok(HttpResponse::Ok().json(&DescribeResponse { active: false, name: None, email: None, picture: None }));
            }

            let name: Option<String> = row.get("name").unwrap();
            let email: Option<String> = row.get("email").unwrap();
            let picture: Option<String> = row.get("picture").unwrap();

            Ok(HttpResponse::Ok().json(&DescribeResponse { active: true, name, email, picture }))
        },
        None => Err(Error::NotFound("The requested user does not exist"))
    }
}