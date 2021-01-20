#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all="kebab-case", deny_unknown_fields)]
pub(crate) struct Hook {
    pub id: String,
    execute_command: String,
    command_working_directory: Option<String>,
    #[serde(default)]
    pass_arguments_to_command: Vec<Argument>,
    #[serde(default)]
    include_command_output_in_response: bool,
    #[serde(default)]
    include_command_output_in_response_on_error: bool,
    response_message: Option<String>,
    #[serde(default)]
    response_headers: Vec<Header>,
    success_http_response_code: Option<u32>,
    incoming_payload_content_type: Option<String>,
    #[serde(default)]
    pass_file_to_command: Vec<File>,
    #[serde(default)]
    pass_environment_to_command: Vec<Environment>,
    #[serde(default)]
    parse_parameters_as_json: Vec<Parameter>,
    #[serde(default)]
    http_methods: Vec<String>,
    trigger_rule: Option<TriggerRules>,
    trigger_rule_mismatch_http_response_code: Option<u32>,
    #[serde(default)]
    trigger_signature_soft_failures: bool,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub(crate) struct Header {
    name: String,
    value: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum Argument {
    Partial(Parameter),
    Entire {
        source: Source,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Deserialize)]
#[serde(rename_all="lowercase", deny_unknown_fields)]
pub(crate) enum Source {
    EntireHeader,
    EntireQuery,
    Header,
    Payload,
    Request,
    String,
    Url,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Parameter {
    source: Source,
    name: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct File {
    source: Source,
    name: String,
    envname: Option<String>,
    base64encode: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Environment {
    envname: String,
    source: Source,
    name: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all="lowercase", deny_unknown_fields)]
pub(crate) enum TriggerRules {
    Match(Match),
    And(Vec<TriggerRule>),
    Or(Vec<TriggerRule>),
    Not(Vec<TriggerRule>),
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all="lowercase", deny_unknown_fields)]
pub(crate) enum TriggerRule {
    Match(Match),
}

#[derive(Clone, Debug, serde::Deserialize)]
pub(crate) struct Match {
    #[serde(flatten)]
    value: Value,
    parameter: Option<Parameter>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all="kebab-case", deny_unknown_fields)]
pub(crate) enum Value {
    Value {
        value: String,
    },
    Regex {
        regex: String,
    },
    PayloadHmacSha1 {
        secret: String,
    },
    PayloadHmacSha256 {
        secret: String,
    },
    PayloadHmacSha512 {
        secret: String,
    },
    #[serde(rename_all="kebab-case")]
    IpWhitelist {
        ip_range: String
    },
    ScalrSignature {
        secret: String,
    },
}

#[cfg(test)]
mod test {
    #[test]
    fn config() {
        let hooks: Result<Vec<crate::config::Hook>, serde_yaml::Error> = serde_yaml::from_str(include_str!("../hooks.yaml"));

        if let Err(err) = &hooks {
            dbg!(err);
        }

        assert!(hooks.is_ok());
    }
}
