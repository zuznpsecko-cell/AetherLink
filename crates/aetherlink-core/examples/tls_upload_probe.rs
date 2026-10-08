//! Upload probe: same outer TLS as production (rustls, system roots,
//! SNI selmedia.ru), no tunnel mechanics. Splits DPI-fingerprint vs stack:
//! if this crawls like the tunnel, the hello is flagged; if it flies, the
//! bottleneck is ours.
//!
//! Usage: cargo run --example tls_upload_probe -- 31.57.158.233 8443 selmedia.ru 5

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (host, port, sni, megs) = match args.as_slice() {
        [_, h, p, s, m] => (
            h.clone(),
            p.parse::<u16>().expect("port"),
            s.clone(),
            m.parse::<usize>().expect("mb"),
        ),
        _ => {
            eprintln!("usage: tls_upload_probe <host> <port> <sni> <megabytes>");
            std::process::exit(2);
        }
    };
    use std::net::ToSocketAddrs;
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .expect("resolve")
        .next()
        .expect("addr");
    eprintln!("probe: connecting {addr} ...");
    let sock = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10))
        .expect("tcp connect");
    eprintln!("probe: tcp ok");
    sock.set_nodelay(true).expect("nodelay");
    let cfg = std::sync::Arc::new(aetherlink_core::tls::system_client_config().expect("tls cfg"));
    let name = aetherlink_core::tls::server_name(&sni).expect("sni");
    let t0 = Instant::now();
    let mut stream = aetherlink_core::tls::connect_tls(sock, name, &cfg).expect("tls handshake");
    eprintln!("probe: handshake ok in {:?}", t0.elapsed());
    let total = megs * 1024 * 1024;
    let chunk = vec![0xABu8; 65536];
    let mut sent = 0usize;
    let mut next_mark = 1024 * 1024;
    let t1 = Instant::now();
    while sent < total {
        let n = chunk.len().min(total - sent);
        stream.write_all(&chunk[..n]).expect("upload write");
        sent += n;
        if sent >= next_mark {
            eprintln!(
                "probe: sent {}MB in {:?}",
                sent / (1024 * 1024),
                t1.elapsed()
            );
            next_mark += 1024 * 1024;
        }
    }
    // Drain one reply so the server side can't RST on close with unread data.
    let mut one = [0u8; 1];
    let _ = stream.read(&mut one);
    let dt = t1.elapsed();
    println!(
        "probe: uploaded={sent}B in {dt:?} = {}B/s",
        (sent as f64 / dt.as_secs_f64()) as u64
    );
}
