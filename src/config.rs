#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct Hook {
    pub id: String,
    pub user: Option<String>,
    pub execute_command: String,
    pub command_working_directory: Option<String>,
    #[serde(default, with = "serde_yaml_ng::with::singleton_map")]
    pub pass_arguments_to_command: Vec<Argument>,
    #[serde(default)]
    pub include_command_output_in_response: bool,
    #[serde(default)]
    pub include_command_output_in_response_on_error: bool,
    pub response_message: Option<String>,
    #[serde(default)]
    pub response_headers: Vec<Header>,
    #[serde(default, deserialize_with = "de::status_code", serialize_with = "se::status_code")]
    pub success_http_response_code: Option<actix_web::http::StatusCode>,
    pub incoming_payload_content_type: Option<String>,
    #[serde(default, with = "serde_yaml_ng::with::singleton_map")]
    pub pass_file_to_command: Vec<Parameter>,
    #[serde(default, with = "serde_yaml_ng::with::singleton_map")]
    pub pass_environment_to_command: Vec<Parameter>,
    #[serde(default, with = "serde_yaml_ng::with::singleton_map")]
    parse_parameters_as_json: Vec<Parameter>,
    #[serde(default, deserialize_with = "de::method", serialize_with = "se::method")]
    pub http_methods: Vec<actix_web::http::Method>,
    #[serde(with = "serde_yaml_ng::with::singleton_map")]
    pub trigger_rule: Option<TriggerRules>,
    #[serde(default, deserialize_with = "de::status_code", serialize_with = "se::status_code")]
    pub trigger_rule_mismatch_http_response_code: Option<actix_web::http::StatusCode>,
    #[serde(default)]
    pub trigger_signature_soft_failures: bool,
}

mod de {
    pub fn method<'de, D>(deserializer: D) -> Result<Vec<actix_web::http::Method>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        use serde::Deserialize;

        let buf = Vec::<String>::deserialize(deserializer)?;

        let mut methods = Vec::new();

        for x in buf {
            let method = actix_web::http::Method::try_from(x.to_uppercase().as_str())
                .map_err(D::Error::custom)?;
            methods.push(method);
        }

        Ok(methods)
    }

    pub fn status_code<'de, D>(
        deserializer: D,
    ) -> Result<Option<actix_web::http::StatusCode>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        use serde::Deserialize;

        let buf = match Option::<u16>::deserialize(deserializer)? {
            Some(buf) => buf,
            None => return Ok(None),
        };

        let status_code = actix_web::http::StatusCode::try_from(buf).map_err(D::Error::custom)?;

        Ok(Some(status_code))
    }
}

mod se {
    pub fn method<S>(value: &Vec<actix_web::http::Method>, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        use serde::ser::SerializeSeq as _;

        let mut seq = serializer.serialize_seq(Some(value.len()))?;

        for e in value {
            seq.serialize_element(e.as_str())?;
        }
        seq.end()
    }

    pub fn status_code<S>(value: &Option<actix_web::http::StatusCode>, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        match value {
            Some(v) => serializer.serialize_some(&v.as_u16()),
            None => serializer.serialize_none(),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum Argument {
    #[serde(with = "serde_yaml_ng::with::singleton_map")]
    Partial(Parameter),
    Entire {
        #[serde(with = "serde_yaml_ng::with::singleton_map")]
        source: Source,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Source {
    EntireHeader,
    EntireQuery,
    EntirePayload,
    Header,
    Payload,
    Request,
    String,
    Url,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum Parameter {
    File {
        #[serde(with = "serde_yaml_ng::with::singleton_map")]
        source: Source,
        name: String,
        envname: Option<String>,
        base64encode: bool,
    },
    Environment {
        envname: Option<String>,
        #[serde(with = "serde_yaml_ng::with::singleton_map")]
        source: Source,
        name: String,
    },
    Param {
        #[serde(with = "serde_yaml_ng::with::singleton_map")]
        source: Source,
        name: String,
    },
}

impl Parameter {
    pub fn name(&self) -> String {
        match self {
            Self::Param { name, .. } => name.clone(),
            Self::File { name, .. } => name.clone(),
            Self::Environment { name, .. } => name.clone(),
        }
    }

    pub fn source(&self) -> &Source {
        match self {
            Self::Param { source, .. } => source,
            Self::File { source, .. } => source,
            Self::Environment { source, .. } => source,
        }
    }

    pub fn envname(&self) -> String {
        match self {
            Self::Environment { name, envname, .. } | Self::File { name, envname, .. } => envname
                .clone()
                .unwrap_or_else(|| format!("HOOK_{name}")),
            _ => self.name(),
        }
    }

    pub fn base64encode(&self) -> bool {
        if let Self::File { base64encode, .. } = self {
            *base64encode
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum TriggerRules {
    #[serde(with = "serde_yaml_ng::with::singleton_map")]
    Match(Match),
    #[serde(with = "serde_yaml_ng::with::singleton_map")]
    Not(Match),
    #[serde(with = "serde_yaml_ng::with::singleton_map")]
    And(Vec<TriggerRule>),
    #[serde(with = "serde_yaml_ng::with::singleton_map")]
    Or(Vec<TriggerRule>),
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct TriggerRule {
    #[serde(rename = "match", with = "serde_yaml_ng::with::singleton_map")]
    r#match: Match,
}

impl std::ops::Deref for TriggerRule {
    type Target = Match;

    fn deref(&self) -> &Match {
        &self.r#match
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Match {
    Value {
        value: String,
        #[serde(with = "serde_yaml_ng::with::singleton_map")]
        parameter: Parameter,
    },
    Regex {
        regex: String,
        #[serde(with = "serde_yaml_ng::with::singleton_map")]
        parameter: Parameter,
    },
    PayloadHmacSha1 {
        secret: String,
        #[serde(with = "serde_yaml_ng::with::singleton_map")]
        parameter: Parameter,
    },
    PayloadHmacSha256 {
        secret: String,
        #[serde(with = "serde_yaml_ng::with::singleton_map")]
        parameter: Parameter,
    },
    PayloadHmacSha512 {
        secret: String,
        #[serde(with = "serde_yaml_ng::with::singleton_map")]
        parameter: Parameter,
    },
    #[serde(rename_all = "kebab-case")]
    IpWhitelist { ip_range: ipnetwork::IpNetwork },
}

impl Match {
    pub fn is_signatrue(&self) -> bool {
        matches!(
            &self,
            Self::PayloadHmacSha1 { .. }
                | Self::PayloadHmacSha256 { .. }
                | Self::PayloadHmacSha512 { .. }
        )
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn config() {
        let hooks: Result<Vec<crate::config::Hook>, serde_yaml_ng::Error> =
            serde_yaml_ng::from_str(include_str!("../hooks.yaml"));

        if let Err(err) = &hooks {
            dbg!(err);
        }

        assert!(hooks.is_ok());
    }
}
