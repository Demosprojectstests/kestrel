use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

struct Inbox {
    boxes: HashMap<String, Vec<Vec<u8>>>,
    prekeys: HashMap<String, Vec<u8>>,
}

fn main() {
    let names = allowlist();
    match &names {
        Some(list) => eprintln!("allowlist on, {} names", list.len()),
        None => eprintln!("allowlist off"),
    }
    let inbox = Arc::new(Mutex::new(Inbox {
        boxes: HashMap::new(),
                                    prekeys: HashMap::new(),
    }));
    let listener = TcpListener::bind("0.0.0.0:7777").expect("bind 7777");
    eprintln!("kestreld listening on 0.0.0.0:7777");

    for incoming in listener.incoming() {
        let Ok(stream) = incoming else { continue };
        let inbox = Arc::clone(&inbox);
        let names = names.clone();
        thread::spawn(move || {
            if let Err(err) = handle(stream, inbox, names) {
                eprintln!("client dropped: {err}");
            }
        });
    }
}

fn allowlist() -> Option<Vec<String>> {
    let path = std::env::var("KESTREL_ALLOW").ok()?;
    let text = std::fs::read_to_string(path).unwrap_or_default();
    Some(
        text.lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect(),
    )
}

fn allowed(names: &Option<Vec<String>>, id: &str) -> bool {
    names.as_ref().map(|list| list.iter().any(|n| n == id)).unwrap_or(true)
}

fn handle(mut stream: TcpStream, inbox: Arc<Mutex<Inbox>>, names: Option<Vec<String>>) -> std::io::Result<()> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > 1_048_576 {
        return Ok(());
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    let (op, rest) = buf.split_at(1);
    match op[0] {
        1 => put(&mut stream, &inbox, rest, &names),
        2 => take(&mut stream, &inbox, rest),
        3 => store_prekey(&mut stream, &inbox, rest, &names),
        4 => fetch_prekey(&mut stream, &inbox, rest),
        other => {
            eprintln!("unknown op {other}");
            stream.write_all(&1u32.to_be_bytes())?;
            stream.write_all(&[0])?;
            Ok(())
        }
    }
}

fn reject(stream: &mut TcpStream, id: &str) -> std::io::Result<()> {
    eprintln!("rejected {id}");
    stream.write_all(&1u32.to_be_bytes())?;
    stream.write_all(&[0])?;
    Ok(())
}

fn store_prekey(
    stream: &mut TcpStream,
    inbox: &Arc<Mutex<Inbox>>,
    rest: &[u8],
    names: &Option<Vec<String>>,
) -> std::io::Result<()> {
    if rest.len() < 2 {
        return Ok(());
    }
    let id_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + id_len {
        return Ok(());
    }
    let id = String::from_utf8_lossy(&rest[2..2 + id_len]).into_owned();
    if !allowed(names, &id) {
        return reject(stream, &id);
    }
    let key = rest[2 + id_len..].to_vec();
    eprintln!("store {id} -> {} bytes", key.len());
    inbox.lock().expect("inbox").prekeys.insert(id, key);
    stream.write_all(&1u32.to_be_bytes())?;
    stream.write_all(&[1])?;
    Ok(())
}

fn fetch_prekey(stream: &mut TcpStream, inbox: &Arc<Mutex<Inbox>>, rest: &[u8]) -> std::io::Result<()> {
    let id = String::from_utf8_lossy(rest).into_owned();
    let key = inbox.lock().expect("inbox").prekeys.get(&id).cloned().unwrap_or_default();
    eprintln!("fetch {id} -> {} bytes", key.len());
    stream.write_all(&(key.len() as u32).to_be_bytes())?;
    stream.write_all(&key)?;
    Ok(())
}

fn put(
    stream: &mut TcpStream,
    inbox: &Arc<Mutex<Inbox>>,
    rest: &[u8],
    names: &Option<Vec<String>>,
) -> std::io::Result<()> {
    if rest.len() < 2 {
        return Ok(());
    }
    let id_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + id_len {
        return Ok(());
    }
    let id = String::from_utf8_lossy(&rest[2..2 + id_len]).into_owned();
    if !allowed(names, &id) {
        return reject(stream, &id);
    }
    let body = rest[2 + id_len..].to_vec();
    eprintln!("queue {id} -> {} bytes", body.len());
    inbox.lock().expect("inbox").boxes.entry(id).or_default().push(body);
    stream.write_all(&1u32.to_be_bytes())?;
    stream.write_all(&[1])?;
    Ok(())
}

fn take(stream: &mut TcpStream, inbox: &Arc<Mutex<Inbox>>, rest: &[u8]) -> std::io::Result<()> {
    let id = String::from_utf8_lossy(rest).into_owned();
    let queued = inbox.lock().expect("inbox").boxes.remove(&id).unwrap_or_default();
    eprintln!("take {id} -> {} blobs", queued.len());
    let mut out = (queued.len() as u32).to_be_bytes().to_vec();
    for item in queued {
        out.extend_from_slice(&(item.len() as u32).to_be_bytes());
        out.extend_from_slice(&item);
    }
    stream.write_all(&(out.len() as u32).to_be_bytes())?;
    stream.write_all(&out)?;
    Ok(())
}
