use common_components::AppData;
use crate::ExtraData;
use crate::env::Env;
use mysql::{prelude::Queryable, Row, Params, params};
use log::warn;

pub mod check;
pub mod describe;

enum SessionError {
    Expired,
    NotFound,
    InternalError
}

fn check_session(data: &AppData<Env, ExtraData>, session_id: &str) -> Result<(), SessionError> {
    let mut conn = match data.get_conn() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create MySQL connection for /endpoints/session/mod/check_session(): {:?}", e);
            return Err(SessionError::InternalError);
        }
    };

    match conn.exec_first::<Row, &str, Params>("SELECT expiry FROM sessions WHERE session_id = :session_id", params! {
        "session_id" => &session_id
    }) {
        Ok(Some(session_row)) => {
            let expiry: i64 = session_row.get("expiry").unwrap();
            if chrono::Utc::now().timestamp() >= expiry {
                match conn.exec_drop("DELETE FROM sessions WHERE session_id = :session_id", params! {
                    "session_id" => &session_id
                }) {
                    Ok(_) => Err(SessionError::Expired),
                    Err(e) => {
                        warn!("Failed to remove session_id '{}' from table 'sessions' in /endpoints/session/mod/check_session(): {:?}", &session_id, e);
                        Err(SessionError::InternalError)
                    }
                }
            } else {
                Ok(())
            }
        },
        Ok(None) => {
            Err(SessionError::NotFound)
        },
        Err(e) => {
            warn!("Failed to query table 'sessions' in /endpoints/session/mod/check_session() {:?}", e);
            Err(SessionError::InternalError)
        }
    }
}