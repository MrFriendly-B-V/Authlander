use crate::env::AppData;
use mysql::{prelude::Queryable, Row, Params, params};
use crate::error::Error;

pub mod check;
pub mod describe;

fn check_session(data: &AppData, session_id: &str) -> Result<(), Error> {
    let mut conn = data.pool.get_conn()?;

    match conn.exec_first::<Row, &str, Params>("SELECT expiry FROM sessions WHERE session_id = :session_id", params! {
        "session_id" => &session_id
    })? {
        Some(session_row) => {
            let expiry: i64 = session_row.get("expiry").unwrap();
            if chrono::Utc::now().timestamp() >= expiry {
                conn.exec_drop("DELETE FROM sessions WHERE session_id = :session_id", params! {
                    "session_id" => &session_id
                })?;

                Err(Error::Unauthorized)
            } else {
                Ok(())
            }
        },
        None => {
            Err(Error::NotFound("Session does not exist"))
        },
    }
}