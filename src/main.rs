#[macro_use]
extern crate log;
extern crate env_logger;

use serde::{Deserialize, Serialize};
use serde_json;
use mysql_async::prelude::*;
use tokio::fs::File;
use tokio::prelude::*;

#[derive(Serialize, Deserialize)]
struct Config {
    host: String,
    port: i32,
    db_host: String,
    db_port: i32,
    db_db: String,
    db_user: String,
    db_password: String,
    ss_config_path: String,
    location: String,
    domain: String,
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    let config_file_path = match args.get(1) {
        None => "/etc/ssguard.json",
        Some(s) => &s,
    };
    let mut file = File::open(config_file_path).await?;
    let mut config_file_data = vec![];
    file.read_to_end(&mut config_file_data).await?;
    let config_file_str = std::str::from_utf8(&config_file_data)?;
    let config: Config = serde_json::from_str(config_file_str)?;
    info!("Load ssguard config file");

    let mut err_cnt = 0;

    let mut saved_ports = vec![];
    let mut last = std::time::Instant::now();

    loop {
        let ports = match monitor_ss(&config).await {
            Ok(v) => v,
            Err(e) => {
                err_cnt += 1;
                error!("{}", e);
                if err_cnt == 1000 {
                    error!("Error count reach the limit");
                    return Err(e);
                }
                error!("Ready to sleep for 20 min");
                std::thread::sleep(std::time::Duration::from_secs(1200));
                continue;
            }
        };
        let curr = std::time::Instant::now();
        if ports == saved_ports && (curr - last).as_secs() > 3600 {
            last = curr;
            continue;
        }
        let mut wait_secs = 4;
        while let Err(e) = update_database(&config, &ports).await {
            error!("Database error: {}", e);
            if wait_secs > 12 * 3600 {
                break;
            }
            error!("Ready to sleep for {} sec", wait_secs);
            std::thread::sleep(std::time::Duration::from_secs(wait_secs));
            wait_secs *= 2;
        }
        saved_ports = ports.clone();
        info!("Written to database");
        std::thread::sleep(std::time::Duration::from_secs(20));
    }
}

async fn monitor_ss(
    config: &Config
) -> Result<Vec<(i32, String)>, Box<dyn std::error::Error>> {
    let mut ss_file = File::open(&config.ss_config_path).await?;
    let mut ss_data = vec![];
    ss_file.read_to_end(&mut ss_data).await?;
    let ss_str = std::str::from_utf8(&ss_data)?;
    let ss_config: serde_json::Value = serde_json::from_str(ss_str)?;
    let mut ports = vec![];
    if let Some(p) = ss_config.get("port_password") {
        if let serde_json::Value::Object(m) = p {
            for (k, v) in m {
                let port_num = k.as_str().parse::<i32>()?;
                let password = v.as_str().ok_or(
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Parse json field error",
                    )
                )?;
                ports.push((port_num, password.to_string()));
            }
        }
    }
    if let Some(port_num) = ss_config.get("server_port") {
        if let Some(password) = ss_config.get("password") {
            let port_num = port_num.as_i64().ok_or(
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Parse json field error",
                )
            )?;
            let password = password.as_str().ok_or(
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Parse json field error",
                )
            )?;
            ports.push((port_num as i32, password.to_string()));
        }
    }
    Ok(ports)
}

async fn update_database(
    config: &Config,
    ports: &Vec<(i32, String)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = mysql_async::Pool::new(
        &format!(
            "mysql://{}:{}@{}:{}/{}",
            config.db_user, config.db_password,
            config.db_host, config.db_port, config.db_db
        )
    );
    let conn = pool.get_conn().await?;
    let read_query = format!(r#"
        SELECT port
        FROM host_info
        WHERE host = '{}'
    "#, config.host);
    let read_result = conn.prep_exec(&read_query, ()).await?;
    let (read_result, rows) = read_result.collect::<i32>().await?;
    let conn = read_result.drop_result().await?;

    let insert_data: Vec<(String, String, String, i32, String)> =
        ports.iter().map(|x| {
            (config.host.clone(), config.domain.clone(), config.location.clone(),
             x.0, x.1.clone())
        }).collect();
    let params = insert_data.into_iter().map(
        |x| {
            params! {
                "host" => x.0,
                "domain" => x.1,
                "location" => x.2,
                "port" => x.3,
                "password" => x.4,
                "method" => "aes-256-cfb",
                "valid" => 1,
            }
        });

    let insert_query = r#"
        INSERT INTO host_info (host, domain, location, port, password, method, valid)
        VALUES (:host, :domain, :location, :port, :password, :method, :valid)
        ON DUPLICATE KEY UPDATE
            domain = :domain,
            location = :location,
            password = :password,
            method = :method,
            valid = :valid
    "#;

    let conn = conn.batch_exec(insert_query, params).await?;

    let to_be_deleted: Vec<i32> = rows.iter().filter(|x| {
        for (port, _) in ports {
            if **x == *port {
                return false;
            }
        }
        true
    }).map(|x| *x).collect();

    if !to_be_deleted.is_empty() {
        let params = to_be_deleted.into_iter().map(
            |x| {
                params! {
                "port" => x
            }
            }
        );

        let delete_query = r#"
            DELETE FROM host_info
            WHERE port = :port
        "#;

        let _ = conn.batch_exec(delete_query, params).await?;
    }

    pool.disconnect().await?;

    Ok(())
}


