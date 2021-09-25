mod env;
mod endpoints;
mod apis;
mod totp;

use crate::env::Env;
use log::{info, error as log_error};
use common_components::{AppData, Result, error as co_error};
use actix_web::{HttpServer, App};
use actix_web::middleware::Logger;

#[derive(Clone)]
pub struct ExtraData {
    tera: tera::Tera,
}

#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    log4rs::init_file("./log4rs.yaml", Default::default()).unwrap();
    info!("Starting Authlander Server");

    let mut tera = match tera::Tera::new("templates/**/*") {
        Ok(t) => t,
        Err(e) => {
            log_error!("Failed to create Tera instance: {:?}", e);
            std::process::exit(1);
        }
    };
    tera.autoescape_on(vec![]);

    let extra = ExtraData { tera };

    let appdata = match AppData::<Env, ExtraData>::new_with_extra("Authlander", extra, |env| -> Result<mysql::Pool> {
        let opts = mysql::OptsBuilder::new()
            .ip_or_hostname(Some(&env.mysql_host))
            .user(Some(&env.mysql_username))
            .pass(Some(&env.mysql_password))
            .db_name(Some(&env.mysql_database))
            .stmt_cache_size(32);

        match mysql::Pool::new(opts) {
            Ok(p) => Ok(p),
            Err(e) => Err(co_error!(e, "Failed to create MySQL Connection Pool"))
        }
    }) {
        Ok(ad) => ad,
        Err(e) => {
            log_error!("Failed to create AppData instance: {}", e);
            std::process::exit(1);
        }
    };

    let mut conn = match appdata.get_conn() {
        Ok(c) => c,
        Err(e) => {
            log_error!("{}", e);
            std::process::exit(1);
        }
    };

    match env::migrate(&mut conn) {
        Ok(_) => {},
        Err(e) => {
            log_error!("Failed to migrate database: {}", e);
            std::process::exit(1);
        }
    }

    HttpServer::new(move || {
        App::new()
            .wrap(actix_cors::Cors::permissive())
            .wrap(Logger::default())
            .data(appdata.clone())
            .service(endpoints::oauth2::login::login)
            .service(endpoints::oauth2::grant::grant)
            .service(endpoints::session::check::check)
            .service(endpoints::session::describe::describe)
            .service(endpoints::token::get::get)
            .service(endpoints::user::scopes::scopes)
            .service(endpoints::user::describe::describe)
            .default_service(actix_web::web::route().to(page_404))
    }).bind("0.0.0.0:8080")?.run().await
}

async fn page_404() -> std::result::Result<actix_web::HttpResponse, actix_web::Error> {
    Ok(actix_web::HttpResponse::NotFound().body("Oei, I cant find that page I'm afraid."))
}
