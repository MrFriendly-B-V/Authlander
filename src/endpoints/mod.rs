use common_components::{AppData, error, Result};
use crate::{env::Env, ExtraData};
use mysql::{prelude::Queryable, Row, Params, params};

pub mod oauth2;
pub mod token;
pub mod session;
pub mod user;

pub fn get_scopes(data: &AppData<Env, ExtraData>, user_id: &str) -> Result<Vec<String>> {
    let mut conn = match data.get_conn() {
        Ok(c) => c,
        Err(e) => return Err(e)
    };

    let rows = match conn.exec::<Row, &str, Params>("SELECT scope_name FROM scopes WHERE user_id = :user_id", params! {
        "user_id" => &user_id
    }) {
        Ok(r) => r,
        Err(e) => return Err(error!(e, "Failed to query scopes"))
    };

    let scopes = rows.into_iter()
        .map(|r| r.get("scope_name").unwrap())
        .collect();

    Ok(scopes)
}