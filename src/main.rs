use std::{net::Ipv4Addr, time::Instant};
use ssh2::Session;
use clap::Parser;
use reqwest::Client;
use tokio::{net::TcpStream, task};
use anyhow::Result;

#[derive(Parser, Debug)]
#[clap(author="CyberNex", version , about="A simple portscanner and hopefully soon a nmap clone written in Rust")]
struct Args{
    ///User supplied IPv4 address of the host they would like to scan
    host: Ipv4Addr,
    #[clap(default_value_t = 1)]
    ///The port number to start the scan on if left blank will default to 1
    start_port: u16,
    #[clap(default_value_t = 1000)]
    ///The port number to end the scan on. If left blank will default to 1000
    end_port: u16,
    #[clap(short = 's', long = "service-check")]
    service_check: bool,
}

struct OpenPort{
    port_info: Vec<(u16, bool, Option<String>)>,
}

async fn web_request(host: Ipv4Addr, port: u16) -> Result<String>{
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let url = if port == 80{
        format!("http://{}:{}", host, port)
    }else if port == 443{
        format!("https://{}:{}", host, port)
    }
    else{
        return Ok(String::new());
    };

    let res = client.get(url).send().await?;
    let body = res.text().await?;
    Ok(body)
}

async fn ssh_info(host: Ipv4Addr, port: u16) ->Result<String>{
    let ssh_version = task::spawn_blocking(move || -> Result<String>{
        let tcp = std::net::TcpStream::connect(format!("{}:{}", host, port))?;
        let mut session = Session::new()?;
        session.set_tcp_stream(tcp);
        session.handshake()?;
        
        let ssh_version = session
            .banner()
            .ok_or_else(||anyhow::anyhow!("No banner returned"))?;

        Ok(ssh_version.to_string())
    })
    .await??;

    Ok(ssh_version)
}

async fn scan_port_chunk(host: Ipv4Addr, ports: Vec<u16>, banner:bool) ->Vec <(u16, bool, Option<String>)>{
    let mut results = Vec::new();
    for port in ports {
        match TcpStream::connect(format!("{}:{}", host,port)).await{
            Ok(_) =>{
                let infobanner = if (port == 80 || port == 443) && banner{
                     web_request(host, port).await.ok()
                }else if port == 22 && banner {
                    ssh_info(host, port).await.ok()
                }else{
                    None
                };
                results.push((port, true, infobanner))
            }
            Err(_) => results.push((port, false, None)),
        }
    }
    results
}

#[tokio::main(flavor ="multi_thread", worker_threads = 5)]
async fn main() {
    let args = Args::parse();
    let start = Instant::now();
    let host = args.host;
    let sport = args.start_port;
    let eport = args.end_port;
    let check_banner = args.service_check;
    let total_ports : Vec<_> = (sport..=eport).collect();
    let chunk_size = total_ports.len() /5;

    println!("Scaning Host: {} Port Range: {}-{}", host, sport, eport);
    let mut tasks = Vec::new();
    for port_chunk in total_ports.chunks(chunk_size) {
        let host = host.clone();
        let chunk: Vec<_> = port_chunk.to_vec();
        let task = tokio::spawn(async move{
            scan_port_chunk(host, chunk, check_banner).await
        });
        tasks.push(task);
    }

    let mut oport = OpenPort{ port_info: Vec::new() };
    for task in tasks{
        let result = task.await.unwrap();
        oport.port_info.extend(result);
        
    }

    for(port, is_open, banner) in &oport.port_info{
        if *is_open {
            if let Some(b) = banner{
                println!("Open Port {}", port);
                println!("Banner {}", b);
            }else{
                println!("Open Port: {}", port);
            }
        }
    }
    let stime = start.elapsed();
    let min = stime.as_secs() / 60;
    let sec = stime.as_secs() % 60;
    let millisec = stime.as_millis();
    let ftime = format!("{}:{}.{}", min, sec, millisec);

    println!("Total scan time {}", ftime);
    
}
