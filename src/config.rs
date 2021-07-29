#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct Hook {
    pub id: String,
    pub user: Option<String>,
    pub execute_command: String,
    pub command_working_directory: Option<String>,
    #[serde(default)]
    pub pass_arguments_to_command: Vec<Argument>,
    #[serde(default)]
    pub include_command_output_in_response: bool,
    #[serde(default)]
    pub include_command_output_in_response_on_error: bool,
    pub response_message: Option<String>,
    #[serde(default)]
    pub response_headers: Vec<Header>,
    #[serde(default, deserialize_with = "de_status_code")]
    pub success_http_response_code: Option<actix_web::http::StatusCode>,
    pub incoming_payload_content_type: Option<String>,
    #[serde(default)]
    pub pass_file_to_command: Vec<Parameter>,
    #[serde(default)]
    pub pass_environment_to_command: Vec<Parameter>,
    #[serde(default)]
    parse_parameters_as_json: Vec<Parameter>,
    #[serde(default, deserialize_with = "de_method")]
    pub http_methods: Vec<actix_web::http::Method>,
    pub trigger_rule: Option<TriggerRules>,
    #[serde(default, deserialize_with = "de_status_code")]
    pub trigger_rule_mismatch_http_response_code: Option<actix_web::http::StatusCode>,
    #[serde(default)]
    pub trigger_signature_soft_failures: bool,
}

fn de_method<'de, D>(deserializer: D) -> Result<Vec<actix_web::http::Method>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    use serde::Deserialize;
    use std::convert::TryFrom;

    let buf = Vec::<String>::deserialize(deserializer)?;

    let mut methods = Vec::new();

    for x in buf {
        let method = actix_web::http::Method::try_from(x.to_uppercase().as_str())
            .map_err(D::Error::custom)?;
        methods.push(method);
    }

    Ok(methods)
}

fn de_status_code<'de, D>(deserializer: D) -> Result<Option<actix_web::http::StatusCode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    use serde::Deserialize;
    use std::convert::TryFrom;

    let buf = match Option::<u16>::deserialize(deserializer)? {
        Some(buf) => buf,
        None => return Ok(None),
    };

    let status_code = actix_web::http::StatusCode::try_from(buf).map_err(D::Error::custom)?;

    Ok(Some(status_code))
}

#[derive(Clone, Debug, serde::Deserialize)]
pub(crate) struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum Argument {
    Partial(Parameter),
    Entire { source: Source },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Deserialize)]
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

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum Parameter {
    File {
        source: Source,
        name: String,
        envname: Option<String>,
        base64encode: bool,
    },
    Environment {
        envname: Option<String>,
        source: Source,
        name: String,
    },
    Param {
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
                .and_then(|x| std::env::var(x).ok())
                .unwrap_or_else(|| format!("HOOK_{}", name)),
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

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum TriggerRules {
    Match(Match),
    Not(Match),
    And(Vec<TriggerRule>),
    Or(Vec<TriggerRule>),
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum TriggerRule {
    Match(Match),
}

impl std::ops::Deref for TriggerRule {
    type Target = Match;

    fn deref(&self) -> &Match {
        match self {
            Self::Match(r#match) => r#match,
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Match {
    Value {
        value: String,
        parameter: Parameter,
    },
    Regex {
        regex: String,
        parameter: Parameter,
    },
    PayloadHmacSha1 {
        secret: String,
        parameter: Parameter,
    },
    PayloadHmacSha256 {
        secret: String,
        parameter: Parameter,
    },
    PayloadHmacSha512 {
        secret: String,
        parameter: Parameter,
    },
    #[serde(rename_all = "kebab-case")]
    IpWhitelist {
        ip_range: ipnetwork::IpNetwork,
    },
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
        let hooks: Result<Vec<crate::config::Hook>, serde_yaml::Error> =
            serde_yaml::from_str(include_str!("../hooks.yaml"));

        if let Err(err) = &hooks {
            dbg!(err);
        }

        assert!(hooks.is_ok());
    }
}
