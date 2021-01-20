pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("Unknow hook '{0}'")]
    NotFound(String),
    #[error("{0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("{0}")]
    Yaml(#[from] serde_yaml::Error),
}

impl Into<actix_web::http::StatusCode> for &Error
{
    fn into(self) -> actix_web::http::StatusCode
    {
        use actix_web::http::StatusCode;

        match self {
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl actix_web::error::ResponseError for Error
{
    fn error_response(&self) -> actix_web::HttpResponse
    {
        let status: actix_web::http::StatusCode = self.into();

        if status.is_client_error() {
            log::warn!("{}", self);
        } else if status.is_server_error() {
            log::error!("{}", self);
        }

        actix_web::HttpResponse::build(status)
            .header(actix_web::http::header::CONTENT_TYPE, "application/json")
            .body("")
    }
}
