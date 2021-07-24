use actix_web::{get, web, HttpRequest, HttpResponse};
use mysql::{prelude::Queryable, Row, Params, params};
use serde::Serialize;
use common_components::{AppData, respond};
use crate::{env::Env, ExtraData};
use log::warn;

#[derive(Serialize)]
struct DescribeResponse {
    active:     bool,
    name:       Option<String>,
    email:      Option<String>,
    picture:    Option<String>,
}

#[get("/user/describe/{user_id}")]
pub async fn describe(data: web::Data<AppData<Env, ExtraData>>, req: HttpRequest, web::Path(user_id): web::Path<String>) -> HttpResponse {
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

    match crate::endpoints::validate_access_token(&data, &access_token) {
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
            warn!("Failed to create MySQL connection in GET /user/scopes: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    match conn.exec_first::<Row, &str, Params>("SELECT active,name,email,picture FROM users WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    }) {
        Ok(Some(row)) => {
            let active: bool = row.get("active").unwrap();
            if !active {
                return HttpResponse::Ok().content_type("application/json").body(respond!(DescribeResponse { active: false, name: None, email: None, picture: None }));
            }

            let name: Option<String> = row.get("name").unwrap();
            let email: Option<String> = row.get("email").unwrap();
            let picture: Option<String> = row.get("picture").unwrap();

            HttpResponse::Ok().content_type("application/json").body(respond!(DescribeResponse { active: true, name, email, picture }))
        },
        Ok(None) => HttpResponse::NotFound().body(respond!("user_id", "No record exists for the provided user_id")),
        Err(e) => {
            warn!("Failed to query table 'users' in GET /user/describe/: {:?}", e);
            HttpResponse::InternalServerError().body(respond!("internal", "Internal error"))
        }
    }
}