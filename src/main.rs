mod env;
mod endpoints;
mod apis;
mod error;

use log::{info, debug, error};
use actix_web::{HttpServer, App};
use actix_web::middleware::Logger;
use std::process::exit;
use std::sync::Arc;
use actix_web::middleware::normalize::TrailingSlash;

#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    log4rs::init_file("./log4rs.yaml", Default::default()).expect("Failed to initialize logger");
    info!("Starting Authlander Server");

    debug!("Reading environment");
    let env: env::Env = match envy::from_env() {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to read environment: {:?}", e);
            exit(1);
        }
    };

    debug!("Creating appdata object");
    let appdata = match env::AppData::new(&env) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to create AppData object: {:?}", e);
            exit(1);
        }
    };

    match appdata.migrate() {
        Ok(_) => {},
        Err(e) => {
            error!("Failed to run migrations: {:?}", e);
            exit(1);
        }
    }

    let appdata_arc = Arc::new(appdata);
    HttpServer::new(move || {
        App::new()
            .wrap(actix_cors::Cors::permissive())
            .wrap(Logger::default())
            .wrap(actix_web::middleware::NormalizePath::new(TrailingSlash::Trim))
            .data(appdata_arc.clone())
            .service(endpoints::oauth2::login::login)
            .service(endpoints::oauth2::grant::grant)
            .service(endpoints::session::check::check)
            .service(endpoints::session::describe::describe)
            .service(endpoints::token::get::get)
            .service(endpoints::user::scopes::scopes)
            .service(endpoints::user::describe::describe)
            .service(endpoints::user::exists::exists)
            .service(endpoints::user::list::list)
            .default_service(actix_web::web::route().to(page_404))
    }).bind("0.0.0.0:8080")?.run().await
}

async fn page_404() -> std::result::Result<actix_web::HttpResponse, actix_web::Error> {
    Ok(actix_web::HttpResponse::NotFound().body("Oei, I cant find that page I'm afraid."))
}
