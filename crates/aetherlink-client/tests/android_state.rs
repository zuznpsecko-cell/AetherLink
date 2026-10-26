//! P1-R7: the Android-driven `Client` flow (L0).
//!
//! Kotlin does: `clientCreate` -> `establish()` -> `clientPlan` ->
//! `clientConnect` -> detach fd -> `clientAttachTun`. This test drives the
//! same order against a real TLS+PSK server and an in-memory TUN:
//! `android_connect` (with a protector) leaves a connected transport,
//! `android_attach_tun_with` starts the pump, `android_status` reports
//! up/pump_alive, and `android_disconnect` stops the pump and closes the
//! transport (the server sees EOF).
//!
//! L0: no device, no privileges.

use std::io::{ErrorKind, Read};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aetherlink_client::lifecycle::SocketHandle;
use aetherlink_client::{Client, ClientError};
use aetherlink_crypto::auth::NonceCache;
use aetherlink_netstack::tun::TunPackets;
use serde_json::{json, Value};

mod tls_accept_all;

use tls_accept_all::AcceptAll;

const PSK: &[u8] = b"phase-p1r7-test-psk-32-bytes-long!!!";

/// In-memory TUN: idle on read, records what the pump writes.
#[derive(Default)]
struct FakeTun {
    sent: Vec<Vec<u8>>,
}

impl TunPackets for FakeTun {
    fn try_recv(&mut self) -> aetherlink_netstack::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn send_packet(&mut self, pkt: &[u8]) -> aetherlink_netstack::Result<()> {
        self.sent.push(pkt.to_vec());
        Ok(())
    }
}

fn client_config(addr: &str) -> Value {
    json!({
        "client": {
            "server_addr": addr,
            "psk": String::from_utf8_lossy(PSK),
            "dns_mode": "tunnel",
            "android": {
                "split": { "mode": "allow", "apps": ["com.example.app"] }
            }
        }
    })
}

/// One-shot TLS+PSK server. Returns how many rounds ended with the client
/// closing the transport (EOF or reset) instead of stalling.
fn spawn_server(listener: TcpListener, rounds: usize) -> std::thread::JoinHandle<usize> {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let chain = vec![rustls::pki_types::CertificateDer::from(
        key.cert.der().to_vec(),
    )];
    let key_der = key.key_pair.serialize_der();
    let cfg = Arc::new(aetherlink_core::tls::server_config(chain, &key_der).expect("server cfg"));
    std::thread::spawn(move || {
        let mut closed = 0;
        for _ in 0..rounds {
            let (sock, _) = listener.accept().expect("accept");
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .expect("read timeout");
            let mut stream = aetherlink_core::tls::accept_tls(sock, &cfg).expect("server tls");
            let cache = NonceCache::new();
            aetherlink_core::session::handshake_server(&mut stream, PSK, &cache)
                .expect("server handshake");
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        closed += 1;
                        break;
                    }
                    Ok(_) => continue,
                    // A released transport may end with EOF (clean), a reset,
                    // or an incomplete TLS close (`UnexpectedEof`) because the
                    // core shuts the socket down instead of saying goodbye.
                    // Only a stalled peer (timeout) means it is still open.
                    Err(e)
                        if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => {
                        closed += 1;
                        break;
                    }
                }
            }
        }
        closed
    })
}

fn status_of(client: &Client) -> Value {
    serde_json::from_str(&client.android_status().expect("status")).expect("status json")
}

/// Wait until the pump threads are running (`attach` returns before they get
/// their first slice).
fn wait_for_pump(client: &Client) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let status = status_of(client);
        if status["up"] == json!(true) && status["pump_alive"] == json!(true) {
            return status;
        }
        assert!(Instant::now() < deadline, "pump never came up: {status}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn connect_attach_report_and_disconnect_in_the_android_order() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = spawn_server(listener, 1);

    let mut client = Client::new(client_config(&addr.to_string())).expect("client");
    let protected = Arc::new(Mutex::new(Vec::<SocketHandle>::new()));
    client
        .android_connect(Some(Arc::new(AcceptAll)), {
            let protected = Arc::clone(&protected);
            move |handle| {
                protected.lock().expect("lock").push(handle);
                true
            }
        })
        .expect("android connect");
    assert_eq!(
        protected.lock().expect("lock").len(),
        1,
        "the transport socket is protected exactly once"
    );

    let tun = Arc::new(Mutex::new(FakeTun::default()));
    client
        .android_attach_tun_with(Arc::clone(&tun))
        .expect("attach tun");

    let status = wait_for_pump(&client);
    assert_eq!(status["up"], json!(true));
    assert_eq!(status["pump_alive"], json!(true));
    assert_eq!(status["server"], json!(addr.to_string()));

    client.android_disconnect().expect("disconnect");
    let status = status_of(&client);
    assert_eq!(status["up"], json!(false), "disconnect must clear up");
    assert_eq!(
        status["pump_alive"],
        json!(false),
        "disconnect must stop the pump"
    );
    assert!(!client.is_up());

    assert_eq!(
        server.join().expect("server thread"),
        1,
        "the server must see the transport close on disconnect"
    );
}

#[test]
fn refused_protection_leaves_the_client_down() {
    let mut client = Client::new(client_config("127.0.0.1:9")).expect("client");

    let err = match client.android_connect(Some(Arc::new(AcceptAll)), |_| false) {
        Ok(()) => panic!("a refused protect() must fail the connect"),
        Err(e) => e,
    };

    assert!(
        matches!(err, ClientError::PermissionDenied(_)),
        "wrong error: {err}"
    );
    assert!(!client.is_up());
    assert_eq!(status_of(&client)["up"], json!(false));
}

#[test]
fn attach_without_connect_is_an_error() {
    let mut client = Client::new(client_config("127.0.0.1:9")).expect("client");
    let tun = Arc::new(Mutex::new(FakeTun::default()));

    let err = client
        .android_attach_tun_with(tun)
        .expect_err("no transport was connected");

    assert!(matches!(err, ClientError::PlatformError(_)), "{err}");
    assert!(!client.is_up());
}

#[test]
fn disconnect_without_connect_is_a_noop() {
    let mut client = Client::new(client_config("127.0.0.1:9")).expect("client");

    client
        .android_disconnect()
        .expect("disconnect must be safe before connect");
    assert!(!client.is_up());
}

#[test]
fn android_plan_carries_the_configured_split() {
    let client = Client::new(client_config("127.0.0.1:9")).expect("client");

    let plan: Value =
        serde_json::from_str(&client.android_plan().expect("plan")).expect("plan json");

    assert_eq!(
        plan["apps"],
        json!({ "mode": "allow", "packages": ["com.example.app"] })
    );
}

#[test]
fn connect_attach_disconnect_can_run_twice() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = spawn_server(listener, 2);

    let mut client = Client::new(client_config(&addr.to_string())).expect("client");
    for round in 1..=2 {
        client
            .android_connect(Some(Arc::new(AcceptAll)), |_| true)
            .unwrap_or_else(|e| panic!("connect {round}: {e}"));
        client
            .android_attach_tun_with(Arc::new(Mutex::new(FakeTun::default())))
            .unwrap_or_else(|e| panic!("attach {round}: {e}"));
        wait_for_pump(&client);
        client
            .android_disconnect()
            .unwrap_or_else(|e| panic!("disconnect {round}: {e}"));
        assert!(!client.is_up(), "round {round} must end down");
    }

    assert_eq!(
        server.join().expect("server thread"),
        2,
        "both transports must be released"
    );
}
