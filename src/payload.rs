use futures_util::stream::StreamExt;

pub(crate) struct Payload {
    raw: Vec<u8>,
    parsed: Type,
}

enum Type {
    Json(serde_json::Value),
    Unknow(String),
}

impl Payload {
    pub async fn new(
        content_type: &str,
        mut payload: actix_web::web::Payload,
    ) -> crate::Result<Self> {
        let mut bytes = actix_web::web::BytesMut::new();

        while let Some(item) = payload.next().await {
            bytes.extend_from_slice(&item?);
        }

        let raw = bytes.to_vec();

        let ty = match content_type {
            "application/json" => {
                let json = serde_json::from_str(&String::from_utf8(raw.clone())?)?;

                Type::Json(json)
            }
            _ => Type::Unknow(content_type.to_string()),
        };

        Ok(Self { raw, parsed: ty })
    }

    pub fn raw(&self) -> &Vec<u8> {
        &self.raw
    }

    pub fn value(&self, name: &str) -> crate::Result<Option<String>> {
        let value = match &self.parsed {
            Type::Json(json) => {
                use json_dotpath::DotPaths;

                json.dot_get(name)?
            }
            Type::Unknow(content_type) => {
                return Err(crate::Error::UnsuportedContentType(content_type.clone()))
            }
        };

        Ok(value)
    }

    pub fn json(&self) -> crate::Result<&serde_json::Value> {
        let json = match &self.parsed {
            Type::Json(json) => json,
            Type::Unknow(content_type) => {
                return Err(crate::Error::UnsuportedContentType(content_type.clone()))
            }
        };

        Ok(json)
    }
}
