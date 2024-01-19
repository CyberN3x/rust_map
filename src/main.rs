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
}

struct OpenPort{
    port_info: Vec<(u16, Option<String>)>,
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


#[tokio::main]
async fn main() {
    let args = Args::parse();
    let mut oport = OpenPort{
        port_info: Vec::new(),
    };
    let start = Instant::now();

    println!("Scaning Host: {}", args.host);
    println!("Port Range: {} - {} ", args.start_port, args.end_port);
    for port in args.start_port..args.end_port + 1{
       match TcpStream::connect(format!("{}:{}", args.host, port)).await{
            Ok(_stream) => {
               let banner = if port == 80 || port == 443{
                    web_request(args.host, port).await.ok()                  
                }
                else if port == 22{
                    ssh_info(args.host, port).await.ok()
                }
                else {
                    None
                };

                oport.port_info.push((port, banner));
            }
            Err(_e) => {
            }
        }
    }

    let stime = start.elapsed();
    let min = stime.as_secs() / 60;
    let sec = stime.as_secs() % 60;
    let millisec = stime.as_millis();
    let ftime = format!("{}:{}.{}", min, sec, millisec);

    for (port, banner) in &oport.port_info{
        if let Some(b) = banner{
            println!("Open Port {}", port);
            println!("Banner {}", b);
        }else{
            println!("Open Port: {}", port);
        }
    }
    println!("Total scan time {}", ftime);
    
}
