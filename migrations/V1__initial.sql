CREATE TABLE states (
    state VARCHAR(32) PRIMARY KEY NOT NULL,
    nonce VARCHAR(128) NOT NULL,
    redirect_uri TEXT NOT NULL
);

CREATE TABLE users (
    user_id VARCHAR(255) PRIMARY KEY NOT NULL,
    active BOOLEAN NOT NULL,
    name VARCHAR(255),
    email VARCHAR(255),
    picture TEXT,
    refresh_token VARCHAR(255)
);

CREATE TABLE sessions
    session_id VARCHAR(32) PRIMARY KEY NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    expiry BIGINT
);

CREATE TABLE api_users (
    api_token VARCHAR(64) PRIMARY KEY NOT NULL,
    active BOOLEAN,
    name VARCHAR(64) NOT NULL
);

CREATE TABLE scopes (
    id INT PRIMARY KEY NOT NULL AUTO_INCREMENT,
    scope_name VARCHAR(32) NOT NULL,
    user_id VARCHAR(32) NOT NULL
)