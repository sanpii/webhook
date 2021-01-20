mod config;
mod errors;

use errors::*;

use structopt::StructOpt;

#[derive(StructOpt)]
struct Opt {
    #[structopt(long)]
    hooks: Vec<String>,
}

#[derive(Clone, Debug)]
struct Data {
    hooks: Vec<config::Hook>,
}

#[actix_web::main]
async fn main() -> crate::Result<()> {
    #[cfg(debug_assertions)]
    dotenv::dotenv().ok();

    env_logger::init();

    let opt = Opt::from_args();

    let ip = std::env::var("LISTEN_IP").expect("Missing LISTEN_IP env variable");
    let port = std::env::var("LISTEN_PORT").expect("Missing LISTEN_IP env variable");
    let bind = format!("{}:{}", ip, port);

    let data = Data {
        hooks: load_hooks(&opt.hooks)?,
    };

    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .data(data.clone())
    })
    .bind(&bind)?
    .run()
    .await?;

    Ok(())
}

fn load_hooks(files: &[String]) -> crate::Result<Vec<config::Hook>> {
    let mut hooks = Vec::new();

    for file in files {
        let contents = std::fs::read(file)?;
        let mut hook: Vec<config::Hook> = serde_yaml::from_str(&String::from_utf8(contents)?)?;

        hooks.append(&mut hook);
    }

    Ok(hooks)
}
