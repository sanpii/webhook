mod config;
mod errors;
mod payload;

use config::*;
use errors::*;
use payload::*;

use clap::Parser;
use std::collections::HashMap;

#[derive(Parser)]
struct Opt {
    #[arg(long)]
    hooks: Vec<String>,
}

#[derive(Clone, Debug)]
struct Data {
    hooks: Vec<Hook>,
}

#[actix_web::main]
async fn main() -> crate::Result<()> {
    #[cfg(debug_assertions)]
    dotenvy::dotenv().ok();

    env_logger::init();

    let opt = Opt::parse();

    let ip = std::env::var("LISTEN_IP").expect("Missing LISTEN_IP env variable");
    let port = std::env::var("LISTEN_PORT").expect("Missing LISTEN_IP env variable");
    let bind = format!("{ip}:{port}");

    let data = Data {
        hooks: load_hooks(&opt.hooks)?,
    };

    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .app_data(data.clone())
            .service(index)
            .service(get)
            .service(post)
    })
    .bind(&bind)?
    .run()
    .await?;

    Ok(())
}

#[actix_web::get("/")]
async fn index() -> String {
    String::new()
}

#[actix_web::get("/hooks/{id}")]
async fn get(
    id: actix_web::web::Path<String>,
    req: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: actix_web::web::Data<Data>,
) -> crate::Result<actix_web::HttpResponse> {
    hooks(req, payload, &id, &data.hooks).await
}

#[actix_web::post("/hooks/{id}")]
async fn post(
    id: actix_web::web::Path<String>,
    req: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: actix_web::web::Data<Data>,
) -> crate::Result<actix_web::HttpResponse> {
    hooks(req, payload, &id, &data.hooks).await
}

async fn hooks(
    req: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    id: &str,
    hooks: &[Hook],
) -> crate::Result<actix_web::HttpResponse> {
    let hook = match hooks.iter().find(|x| x.id == id) {
        Some(hook) => hook,
        None => return Err(Error::NotFound(id.to_string())),
    };

    log::info!("Found hook '{}'", hook.id);

    let content_type = hook
        .incoming_payload_content_type
        .clone()
        .or_else(|| {
            req.headers()
                .get("content-type")
                .map(|x| x.to_str().unwrap().split(';').next().unwrap().to_string())
        })
        .unwrap_or_else(|| "text/plain".to_string());
    let payload = Payload::new(&content_type, payload).await?;

    if !should_trigger(hook, &payload, &req)? {
        let status_code = hook
            .trigger_rule_mismatch_http_response_code
            .unwrap_or(actix_web::http::StatusCode::FORBIDDEN);
        return Err(Error::Unauthorized(status_code));
    }

    let mut command = std::process::Command::new(&hook.execute_command);

    if let Some(current_dir) = &hook.command_working_directory {
        command.current_dir(current_dir);
    }

    for arg in &hook.pass_arguments_to_command {
        let value = match arg {
            Argument::Partial(param) => get_parameter(param, &payload, &req)?,
            Argument::Entire { source } => match source {
                Source::EntireHeader => {
                    let headers = req
                        .headers()
                        .into_iter()
                        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
                        .collect::<HashMap<String, String>>();
                    serde_json::to_value(&headers)?
                }
                Source::EntireQuery => {
                    let query = form_urlencoded::parse(req.query_string().as_bytes())
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect::<HashMap<String, String>>();
                    serde_json::to_value(query)?
                }
                Source::EntirePayload => payload.json()?.clone(),
                _ => unreachable!(),
            }
            .to_string(),
        };

        command.arg(&value);
    }

    for env in &hook.pass_environment_to_command {
        let envname = env.envname();
        let value = get_parameter(env, &payload, &req)?;

        command.env(envname, value);
    }

    let mut files_to_delete = Vec::new();

    for file in &hook.pass_file_to_command {
        let filename = file.envname();
        let dir = hook
            .command_working_directory
            .clone()
            .unwrap_or_else(|| "/tmp".to_string());
        let path = format!("{dir}/{filename}");

        let value = get_parameter(file, &payload, &req)?;
        let contents = if file.base64encode() {
            use base64::Engine;

            base64::engine::general_purpose::STANDARD.decode(value)?
        } else {
            value.as_bytes().to_vec()
        };

        std::fs::write(&path, contents)?;

        files_to_delete.push(path);
    }

    #[cfg(not(unix))]
    log::warn!("User option is only supported on unix platform");

    #[cfg(unix)]
    if let Some(username) = &hook.user {
        use std::os::unix::process::CommandExt;

        match users::get_user_by_name(&username) {
            Some(user) => {
                command.uid(user.uid());
                command.gid(user.primary_group_id());
            }
            None => log::warn!("Unknow user {}", username),
        }
    }

    log::debug!("Execute {:?}", command);

    let output = command.output()?;
    let response = response(hook, &output);

    for file in files_to_delete {
        std::fs::remove_file(file)?;
    }

    Ok(response)
}

fn load_hooks(files: &[String]) -> crate::Result<Vec<Hook>> {
    let mut hooks = Vec::new();

    for file in files {
        let contents = std::fs::read(file)?;
        let mut hook: Vec<Hook> = serde_yaml::from_str(&String::from_utf8(contents)?)?;

        hooks.append(&mut hook);
    }

    Ok(hooks)
}

fn get_parameter(
    parameter: &Parameter,
    payload: &Payload,
    req: &actix_web::HttpRequest,
) -> crate::Result<String> {
    let name = parameter.name();

    let value = match parameter.source() {
        Source::Header => req
            .headers()
            .get(&name)
            .ok_or_else(|| Error::MissingArgument(name.clone()))?
            .to_str()?
            .to_string(),
        Source::Payload => payload
            .value(&name)?
            .ok_or_else(|| Error::MissingArgument(name.clone()))?,
        Source::String => name,
        Source::Request => match name.as_str() {
            "method" => req.method().as_str().to_string(),
            "remote-addr" => req
                .peer_addr()
                .ok_or_else(|| Error::MissingArgument(name.clone()))?
                .ip()
                .to_string(),
            _ => return Err(Error::UnsupportedRequestKey(name)),
        },
        Source::Url => {
            let mut query = form_urlencoded::parse(req.query_string().as_bytes());

            query
                .find(|(k, _)| *k == name)
                .ok_or_else(|| Error::MissingArgument(name.clone()))?
                .1
                .into_owned()
        }
        _ => unreachable!(),
    };

    Ok(value)
}

fn response(hook: &Hook, output: &std::process::Output) -> actix_web::HttpResponse {
    let status_code = if output.status.success() {
        hook.success_http_response_code
            .unwrap_or(actix_web::http::StatusCode::OK)
    } else {
        hook.trigger_rule_mismatch_http_response_code
            .unwrap_or(actix_web::http::StatusCode::BAD_REQUEST)
    };

    let mut response = actix_web::HttpResponse::build(status_code);
    response.insert_header((
        actix_web::http::header::CONTENT_TYPE,
        "text/plain; charset=utf-8",
    ));

    for header in &hook.response_headers {
        response.insert_header((header.name.as_str(), header.value.as_str()));
    }

    let response = if hook.include_command_output_in_response {
        if output.status.success() {
            response.body(
                String::from_utf8(output.stdout.to_vec())
                    .unwrap_or_else(|_| "Invalid UTF8 output".to_string()),
            )
        } else if hook.include_command_output_in_response_on_error {
            response.insert_header((
                actix_web::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            ));
            response.body(
                String::from_utf8(output.stderr.to_vec())
                    .unwrap_or_else(|_| "Invalid UTF8 output".to_string()),
            )
        } else {
            response.body("Error occurred while executing the hook's command. Please check your logs for more details.")
        }
    } else {
        response.body(hook.response_message.clone().unwrap_or_default())
    };

    response
}

fn should_trigger(
    hook: &Hook,
    payload: &Payload,
    req: &actix_web::HttpRequest,
) -> crate::Result<bool> {
    if !hook.http_methods.is_empty() && !hook.http_methods.contains(req.method()) {
        dbg!(&hook.http_methods, &req.method());
        return Ok(false);
    }

    if let Some(trigger_rule) = &hook.trigger_rule {
        match trigger_rule {
            TriggerRules::Match(r#match) => is_match(r#match, payload, req),
            TriggerRules::Not(r#match) => is_match(r#match, payload, req).map(|x| !x),
            TriggerRules::And(matches) => matches
                .iter()
                .try_fold(true, |acc, x| Ok(acc && is_match(x, payload, req)?)),
            TriggerRules::Or(matches) => matches.iter().try_fold(false, |acc, x| {
                Ok(acc
                    || (x.is_signatrue() && hook.trigger_signature_soft_failures)
                    || is_match(x, payload, req)?)
            }),
        }
    } else {
        Ok(true)
    }
}

fn is_match(
    r#match: &Match,
    payload: &Payload,
    req: &actix_web::HttpRequest,
) -> crate::Result<bool> {
    let is_match = match r#match {
        Match::Value { value, parameter } => &get_parameter(parameter, payload, req)? == value,
        Match::Regex { regex, parameter } => {
            let re = regex::Regex::new(regex)?;
            let value = get_parameter(parameter, payload, req)?;

            re.is_match(&value)
        }
        Match::PayloadHmacSha1 { secret, parameter } => hmac(
            ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            secret,
            parameter,
            payload,
            req,
        )?,
        Match::PayloadHmacSha256 { secret, parameter } => {
            hmac(ring::hmac::HMAC_SHA256, secret, parameter, payload, req)?
        }
        Match::PayloadHmacSha512 { secret, parameter } => {
            hmac(ring::hmac::HMAC_SHA512, secret, parameter, payload, req)?
        }
        Match::IpWhitelist { ip_range } => {
            let peer_addr = match req.peer_addr() {
                Some(peer_addr) => peer_addr,
                None => return Err(Error::MissingPeerAddr),
            };

            ip_range.contains(peer_addr.ip())
        }
    };

    Ok(is_match)
}

fn hmac(
    algo: ring::hmac::Algorithm,
    secret: &str,
    parameter: &Parameter,
    payload: &Payload,
    req: &actix_web::HttpRequest,
) -> crate::Result<bool> {
    let key = ring::hmac::Key::new(algo, secret.as_bytes());
    let body = payload.raw();

    let param = get_parameter(parameter, payload, req)?;
    let tag = param
        .split('=')
        .nth(1)
        .ok_or(Error::InvalidHmac)
        .and_then(|x| hex::decode(x).map_err(|_| Error::InvalidHmac))?;

    let valid = ring::hmac::verify(&key, body, &tag).is_ok();

    Ok(valid)
}
