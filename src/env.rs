use serde::Deserialize;
use mysql::OptsBuilder;
use anyhow::Result;

#[derive(Clone, Deserialize)]
pub struct Env {
    mysql_host:             String,
    mysql_database:         String,
    mysql_username:         String,
    mysql_password:         String,
    pub google_client_id:       String,
    pub google_client_secret:   String,
    pub host:                   String,
}

pub struct AppData {
    pub pool:   mysql::Pool,
    pub env:    Env,
    pub tera:   tera::Tera,
}

mod migrations {
    use refinery::embed_migrations;
    embed_migrations!("./migrations");
}

impl AppData {
    pub fn new(env: &Env) -> Result<Self> {
        let options = OptsBuilder::new()
            .ip_or_hostname(Some(&env.mysql_host))
            .user(Some(&env.mysql_username))
            .pass(Some(&env.mysql_password))
            .db_name(Some(&env.mysql_database));
        let pool = mysql::Pool::new(options)?;

        let mut tera = tera::Tera::new("templates/**/*")?;
        tera.autoescape_on(vec![]);

        Ok(Self {
            pool,
            env: env.clone(),
            tera,
        })
    }

    pub fn migrate(&self) -> Result<()> {
        let mut conn = self.pool.get_conn()?;
        migrations::migrations::runner().run(&mut conn)?;
        Ok(())
    }
}