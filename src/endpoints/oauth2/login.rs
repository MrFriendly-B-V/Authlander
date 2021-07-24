use actix_web::{get, web, HttpRequest, HttpResponse};
use mysql::{prelude::Queryable, params};
use crate::env::Env;
use common_components::{AppData, respond};
use log::{info, warn};
use serde::{Serialize, Deserialize};
use rand::Rng;
use crate::ExtraData;

#[derive(Deserialize)]
struct LoginQuery {
    api_name:           String,
    return_uri:         String,
    requested_scopes:   Option<String>,
}

#[derive(Serialize)]
struct GoogleLoginQuery<'a> {
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
pub async fn login(data: web::Data<AppData<Env, ExtraData>>, req: HttpRequest) -> HttpResponse {
    let login_query: LoginQuery = match serde_qs::from_str(req.query_string()) {
        Ok(q) => q,
        Err(e) => {
            warn!("Failed to parse query parameters for GET /oauth2/login: {:?}", &e);
            return HttpResponse::BadRequest().body(respond!("query", format!("{:?}", &e)))
        }
    };

    info!("Got Oauth2 Login Request on GET /oauth2/login from API '{}'", &login_query.api_name);

    let state: String = rand::thread_rng().sample_iter(rand::distributions::Alphanumeric).take(32).map(char::from).collect();
    let nonce: String = rand::thread_rng().sample_iter(rand::distributions::Alphanumeric).take(128).map(char::from).collect();

    let mut conn = match data.get_conn() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create MySQL Connection for GET /oauth2/login: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    match conn.exec_drop("INSERT INTO states (state, nonce, redirect_uri) VALUES (:state, :nonce, :redirect_uri)", params! {
        "state" => &state,
        "nonce" => &nonce,
        "redirect_uri" => &login_query.return_uri
    }) {
        Ok(_) => {},
        Err(e) => {
            warn!("Failed to insert into table 'states' for GET /oauth2/login: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    }

    let scopes = if let Some(scopes) = login_query.requested_scopes {
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

    let query_params = match serde_qs::to_string(&google_query_params) {
        Ok(qp) => qp,
        Err(e) => {
            warn!("Failed to serialize GoogleLoginQuery parameters to String in GET /oauth2/login: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };
    let redirect_uri = format!("{}?{}", GOOGLE_AUTH_URL, query_params);

    let mut ctx = tera::Context::new();
    ctx.insert("redirect_uri", &redirect_uri);

    let body = match data.extra.as_ref().unwrap().tera.render("redirect.html", &ctx) {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to render Tera template 'redirect.html' in GET /oauth2/login: {:?}", e);
            return HttpResponse::InternalServerError().body(respond!("internal", "Internal error"));
        }
    };

    HttpResponse::Ok().body(body)
}

