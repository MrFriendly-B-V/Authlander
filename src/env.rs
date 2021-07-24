use serde::{Serialize, Deserialize};
use common_components::Result;
use mysql::{prelude::Queryable, Params::Empty};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Env {
    pub mysql_host:             String,
    pub mysql_database:         String,
    pub mysql_username:         String,
    pub mysql_password:         String,
    pub google_client_id:       String,
    pub google_client_secret:   String,
    pub host:                   String,
}

macro_rules! unwrap {
    ($table_name:expr, $input:expr) => {
        match $input {
            Ok(_) => {},
            Err(e) => return Err(common_components::error!(e, format!("Failed to migrate table '{}'", $table_name)))
        }
    }
}

pub fn migrate(conn: &mut mysql::PooledConn) -> Result<()> {
    unwrap!("states", conn.exec_drop("CREATE TABLE IF NOT EXISTS states (`state` varchar(32) PRIMARY KEY NOT NULL, `nonce` varchar(128) NOT NULL, redirect_uri TEXT NOT NULL)", Empty));
    unwrap!("users", conn.exec_drop("CREATE TABLE IF NOT EXISTS users (`user_id` varchar(255) PRIMARY KEY NOT NULL, `active` BOOLEAN NOT NULL, `name` varchar(255), `email` varchar(255), `picture` TEXT, `refresh_token` varchar(255))", Empty));
    unwrap!("sessions", conn.exec_drop("CREATE TABLE IF NOT EXISTS sessions (`session_id` varchar(32) PRIMARY KEY NOT NULL, `user_id` varchar(255) NOT NULL, expiry BIGINT)", Empty));
    unwrap!("api_users", conn.exec_drop("CREATE TABLE IF NOT EXISTS api_users (`api_token` varchar(64) PRIMARY KEY NOT NULL, `active` BOOLEAN, `name` varchar(64) NOT NULL)", Empty));
    unwrap!("scopes", conn.exec_drop("CREATE TABLE IF NOT EXISTS scopes (`id` int PRIMARY KEY NOT NULL AUTO_INCREMENT, `scope_name` varchar(32) NOT NULL, `user_id` varchar(32) NOT NULL)", Empty));

    Ok(())
}