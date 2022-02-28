pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invadid base64 content: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Command fail: {0}")]
    Execute(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid header value: {0}")]
    InvalidHeader(#[from] actix_web::http::header::ToStrError),
    #[error("Invalid hmac value")]
    InvalidHmac,
    #[error("Invalid regex: {0}")]
    InvalidRegex(#[from] regex::Error),
    #[error("Invalid JSON payload: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid JSON path: {0}")]
    JsonPath(#[from] json_dotpath::Error),
    #[error("Unknow hook '{0}'")]
    NotFound(String),
    #[error("Missing argument '{0}'")]
    MissingArgument(String),
    #[error("Missing peer address")]
    MissingPeerAddr,
    #[error("Invalid payload: {0}")]
    Payload(#[from] actix_web::error::PayloadError),
    #[error("{0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("Unauthorized")]
    Unauthorized(actix_web::http::StatusCode),
    #[error("Unsuported content-type: {0}")]
    UnsuportedContentType(String),
    #[error("Unsupported request key: {0}")]
    UnsupportedRequestKey(String),
    #[error("{0}")]
    Yaml(#[from] serde_yaml::Error),
}

impl From<&Error> for actix_web::http::StatusCode {
    fn from(error: &Error) -> Self {
        use actix_web::http::StatusCode;

        match error {
            Error::JsonPath(_) => StatusCode::BAD_REQUEST,
            Error::Json(_) => StatusCode::BAD_REQUEST,
            Error::MissingArgument(_) => StatusCode::BAD_REQUEST,
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            Error::Unauthorized(status_code) => *status_code,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl actix_web::error::ResponseError for Error {
    fn error_response(&self) -> actix_web::HttpResponse {
        let status: actix_web::http::StatusCode = self.into();

        if status.is_client_error() {
            log::warn!("{}", self);
        } else if status.is_server_error() {
            log::error!("{}", self);
        }

        actix_web::HttpResponse::build(status)
            .append_header((
                actix_web::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            ))
            .body(self.to_string())
    }
}
