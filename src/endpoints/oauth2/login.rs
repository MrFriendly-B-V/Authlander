use actix_web::{get, web, HttpResponse};
use mysql::{prelude::Queryable, params};
use crate::env::AppData;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use rand::Rng;
use crate::error::HttpResult;

#[derive(Deserialize)]
pub struct LoginQuery {
    #[allow(unused)]
    api_name:           String,
    return_uri:         String,
    requested_scopes:   Option<String>,
}

#[derive(Serialize)]
pub struct GoogleLoginQuery<'a> {
    client_id:              &'a str,
    redirect_uri:           &'a str,
    response_type:          &'static str,
    scope:                  &'a str,
    access_type:            &'static str,
    state:                  &'a str,
    include_granted_scopes: bool,
    promt:                  &'static str,
    nonce:                  &'a str,
}

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const DEFAULT_SCOPES: &str = "openid profile email";

#[get("/oauth2/login")]
pub async fn login(data: web::Data<Arc<AppData>>, query: web::Query<LoginQuery>) -> HttpResult {
    let state: String = rand::thread_rng().sample_iter(rand::distributions::Alphanumeric).take(32).map(char::from).collect();
    let nonce: String = rand::thread_rng().sample_iter(rand::distributions::Alphanumeric).take(128).map(char::from).collect();

    let mut conn = data.pool.get_conn()?;

    conn.exec_drop("INSERT INTO states (state, nonce, redirect_uri) VALUES (:state, :nonce, :redirect_uri)", params! {
        "state" => &state,
        "nonce" => &nonce,
        "redirect_uri" => &query.return_uri
    })?;

    let scopes = if let Some(scopes) = &query.requested_scopes {
        format!("{} {}", DEFAULT_SCOPES, scopes)
    } else {
        DEFAULT_SCOPES.to_string()
    };

    let google_query_params = GoogleLoginQuery {
        client_id:              &data.env.google_client_id,
        redirect_uri:           &format!("{}/oauth2/grant", &data.env.host),
        response_type:          "code",
        scope:                  &scopes,
        access_type:            "offline",
        state:                  &state,
        include_granted_scopes: true,
        promt:                  "select_account",
        nonce:                  &nonce,
    };

    let query_params = serde_qs::to_string(&google_query_params)?;
    let redirect_uri = format!("{}?{}", GOOGLE_AUTH_URL, query_params);

    let mut ctx = tera::Context::new();
    ctx.insert("redirect_uri", &redirect_uri);

    let body = data.tera.render("redirect.html", &ctx)?;
    Ok(HttpResponse::Ok().body(body))
}

