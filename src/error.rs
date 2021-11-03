use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use thiserror::Error;
use log::warn;

pub type HttpResult = Result<HttpResponse, Error>;

#[derive(Serialize)]
struct ErrorResponse {
    code:       u16,
    message:    String
}

impl From<&Error> for ErrorResponse {
    fn from(e: &Error) -> Self {
        Self {
            code: e.status_code().as_u16(),
            message: format!("{}", e)
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Internal Server Error")]
    Mysql(#[from] mysql::Error),
    #[error("Internal Server Error")]
    Anyhow(#[from] anyhow::Error),
    #[error("Internal Server Error")]
    SerdeQs(#[from] serde_qs::Error),
    #[error("Internal Server Error")]
    Tera(#[from] tera::Error),
    #[error("Internal Server Error")]
    Base64(#[from] base64::DecodeError),
    #[error("Internal Server Error")]
    FromUtf8(#[from] std::string::FromUtf8Error),
    #[error("Internal Server Error")]
    SerdeJson(#[from] serde_json::Error),
    #[error("The requested resource was not found: {0}")]
    NotFound(&'static str),
    #[error("The user did not provide an authorization token, their session has expired, or is not authorized to access the requested resource")]
    Unauthorized,
    #[error("Bad request: {0}")]
    BadRequest(&'static str),
    #[error("Authorization error: {0}")]
    UnauthorizedMsg(&'static str),
    #[error("{0}")]
    Conflict(&'static str)
}

impl Error {
    fn log(&self) {
        match self {
            Self::Mysql(e) => warn!("{:?}", e),
            Self::Anyhow(e) => warn!("{:?}", e),
            _ => {}
        }
    }
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Mysql(_)  | Self::Anyhow(_)
            | Self::SerdeJson(_) | Self::SerdeQs(_) | Self::Tera(_)
            | Self::Base64(_) | Self::FromUtf8(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Unauthorized | Self::UnauthorizedMsg(_) => StatusCode::UNAUTHORIZED,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> HttpResponse {
        self.log();
        let er = ErrorResponse::from(self);
        HttpResponse::build(self.status_code()).json(&er)
    }
}