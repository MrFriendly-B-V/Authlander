use actix_web::{get, web, HttpResponse};
use mysql::{prelude::Queryable, Row, Params, params};
use serde::Serialize;
use crate::{env::Env, ExtraData};
use common_components::{AppData, respond};
use log::warn;

#[derive(Serialize)]
struct ScopesResponse {
    scopes:     Vec<String>,
    is_active:  bool
}

#[get("/user/scopes/{user_id}")]
pub async fn scopes(data: web::Data<AppData<Env, ExtraData>>, web::Path(user_id): web::Path<String>) -> HttpResponse {
    let mut conn = match data.get_conn() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create MySQL connection in GET /user/scopes: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    match conn.exec_first::<Row, &str, Params>("SELECT active FROM users WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    }) {
        Ok(Some(row)) => {
            let active: bool = row.get("active").unwrap();

            if !active {
                return HttpResponse::Ok().content_type("application/json").body(respond!(ScopesResponse { scopes: vec![], is_active: false }));
            }
        },
        Ok(None) => return HttpResponse::NotFound().body(respond!("user_id", "No user exists for the provided user_id")),
        Err(e) => {
            warn!("Failed to query table 'users' in GET /user/has-scope/: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    let scopes = match crate::endpoints::get_scopes(&data, &user_id) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to fetch scopes for user '{}' in GET /user/has-scope/: {}", &user_id, e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    HttpResponse::Ok().content_type("application/json").body(respond!(ScopesResponse { is_active: true, scopes }))
}
