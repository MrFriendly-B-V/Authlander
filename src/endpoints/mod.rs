use crate::env::AppData;
use mysql::{prelude::Queryable, Row, Params, params};

pub mod oauth2;
pub mod token;
pub mod session;
pub mod user;

#[macro_export]
macro_rules! check_token {
    ($req:expr, $data:expr) => {
        {
            match crate::endpoints::validate_access_token(&$data, &$crate::authorization!($req))? {
                true => {},
                false => return Err($crate::error::Error::Unauthorized),
            }
        }
    }
}

#[macro_export]
macro_rules! authorization {
    ($req:expr) => {
        {
            let access_token: String = match $req.headers().get("authorization") {
                Some(at) => match at.to_str() {
                    Ok(at) => at.to_string(),
                    Err(_) => {
                        return Err($crate::error::Error::Unauthorized);
                    }
                },
                None => {
                    return Err($crate::error::Error::Unauthorized);
                }
            };

            access_token
        }
    }
}

pub fn validate_access_token<S: AsRef<str>>(data: &AppData, api_token: S) -> anyhow::Result<bool> {
    let mut conn = data.pool.get_conn()?;

    match conn.exec_first::<Row, &str, Params>("SELECT active FROM api_users WHERE api_token = :api_token", params! {
        "api_token" => api_token.as_ref()
    })? {
        Some(row) => {
            let active: bool = row.get("active").unwrap();
            Ok(active)
        },
        None=> {
            Ok(false)
        }
    }
}

pub fn get_scopes<S: AsRef<str>>(data: &AppData, user_id: S) -> anyhow::Result<Vec<String>> {
    let mut conn = data.pool.get_conn()?;

    let rows = conn.exec::<Row, &str, Params>("SELECT scope_name FROM scopes WHERE user_id = :user_id", params! {
        "user_id" => user_id.as_ref()
    })?;

    let scopes = rows.into_iter()
        .map(|r| r.get("scope_name").unwrap())
        .collect();

    Ok(scopes)
}