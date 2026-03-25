// Run: cargo run --release -- 0.0.0.0:9000

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

type WaitMap = Arc<Mutex<HashMap<String, TcpStream>>>;

fn pipe(mut a: TcpStream, mut b: TcpStream) {
    let mut a2 = a.try_clone().unwrap();
    let mut b2 = b.try_clone().unwrap();
    thread::spawn(move || { std::io::copy(&mut a, &mut b2).ok(); b2.shutdown(std::net::Shutdown::Write).ok(); });
    thread::spawn(move || { std::io::copy(&mut b, &mut a2).ok(); a2.shutdown(std::net::Shutdown::Write).ok(); });
}

fn handle(mut stream: TcpStream, waiting: WaitMap) {
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 { return; }
    let line = line.trim().to_string();

    if let Some(code) = line.strip_prefix("RECEIVER ") {
        let code = code.trim().to_string();
        println!("RECEIVER {} code={}", peer, code);
        waiting.lock().unwrap().insert(code, stream);
    } else if let Some(code) = line.strip_prefix("SENDER ") {
        let code = code.trim().to_string();
        println!("SENDER {} code={}", peer, code);
        let receiver = waiting.lock().unwrap().remove(&code);
        match receiver {
            Some(mut recv_stream) => {
                let hn = peer.clone();
                // Notify both sides
                let _ = writeln!(recv_stream, "PAIRED {}", hn);
                let _ = recv_stream.flush();
                let _ = writeln!(stream, "PAIRED receiver");
                let _ = stream.flush();
                pipe(stream, recv_stream);
            }
            None => {
                let _ = writeln!(stream, "NOT_FOUND");
            }
        }
    }
}

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:9000".into());
    let listener = TcpListener::bind(&addr).expect("Cannot bind");
    println!("rfshare relay listening on {}", addr);
    let waiting: WaitMap = Arc::new(Mutex::new(HashMap::new()));

    // Expire waiting sessions after 5 minutes
    let w2 = Arc::clone(&waiting);
    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(300));
        w2.lock().unwrap().clear();
        println!("Expired all waiting sessions");
    });

    for stream in listener.incoming().flatten() {
        let w = Arc::clone(&waiting);
        thread::spawn(move || handle(stream, w));
    }
}
