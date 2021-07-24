use common_components::{AppData, Result, error};
use crate::env::Env;
use crate::ExtraData;
use mysql::{prelude::Queryable, Row, Params, params};

pub mod get;

pub fn validate_access_token(data: &AppData<Env, ExtraData>, api_token: &str) -> Result<bool> {
    let mut conn = match data.get_conn() {
        Ok(c) => c,
        Err(e) => return Err(e)
    };

    match conn.exec_first::<Row, &str, Params>("SELECT active FROM api_users WHERE api_token = :api_token", params! {
        "api_token" => &api_token
    }) {
        Ok(Some(row)) => {
            let active: bool = row.get("active").unwrap();
            Ok(active)
        },
        Ok(None) => {
            Ok(false)
        }
        Err(e) => Err(error!(e, "Failed to query table 'api_users'"))
    }
}