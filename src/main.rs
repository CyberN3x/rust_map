use std::net::Ipv4Addr;
use clap::Parser;
use tokio::net::TcpStream;

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
    port: Vec<u16>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let mut oport = OpenPort{
        port: Vec::new(),
    };

    println!("Scaning Host: {}", args.host);
    println!("Port Range: {} - {} ", args.start_port, args.end_port);

    for port in args.start_port..args.end_port + 1{
       match TcpStream::connect(format!("{}:{}", args.host, port)).await{
            Ok(_stream) => {
                oport.port.push(port);
            }Err(_e) => {
            }
        }
    }

    for i in &oport.port {
        println!("Open Port: {}", i);
    }
  
}