use std::env;
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use hkdf::Hkdf;
use sha2::Sha256;

use kestrel_crypto::{
    open_message, seal_message, unwrap_prekey, wrap_prekey, HybridPublic, HybridSecret, Identity,
    PublicIdentity, SealedMessage, VerifyError,
};

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("demo") => demo(),
        Some("chat") => {
            let me = args.next().expect("my id");
            let them = args.next().expect("their id");
            let relay = args.next().unwrap_or_else(|| "127.0.0.1:7777".into());
            chat(&me, &them, &relay);
        }
        _ => eprintln!("usage:\n  kestrel demo\n  kestrel chat <me> <them> [host:port]"),
    }
}

fn demo() {
    let alice = Identity::generate();
    let (bob_secret, bob_public) = HybridSecret::generate();
    let sealed = seal_message(&alice, &bob_public, b"kestrel");
    let opened = open_message(&bob_secret, &alice.public(), &sealed).expect("open");
    assert_eq!(opened, b"kestrel");
    println!("roundtrip ok, {} ciphertext bytes", sealed.body.len());
}

fn chat(me_id: &str, them: &str, relay: &str) {
    let code = prompt("connection code: ");
    if code.is_empty() {
        return;
    }
    let me = Identity::generate();
    let (secret, public) = HybridSecret::generate();
    let slot = session_slot(me_id, them, &code);
    let mine = format!("{slot}:{me_id}");
    let theirs = format!("{slot}:{them}");

    publish(relay, &mine, &wrap_prekey(&code, &public.to_bytes()));
    let their_public = wait_prekey(relay, &theirs, &code);
    println!("session {slot} ready. empty line quits.");

    let relay_poll = relay.to_string();
    let mine_poll = mine.clone();
    let secret_poll = Arc::new(secret);
    std::thread::spawn(move || loop {
        let mut frame = vec![2u8];
        frame.extend_from_slice(mine_poll.as_bytes());
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            frame_send(&relay_poll, &frame)
        })) {
            Ok(reply) => print_inbox(&secret_poll, &reply, ""),
                       Err(_) => eprintln!("poll lost the relay, retrying"),
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    });

    for line in std::io::stdin().lines() {
        let line = line.unwrap_or_default();
        if line.is_empty() {
            break;
        }
        println!("me: {line}");
        let sealed = seal_message(&me, &their_public, line.as_bytes());
        queue(relay, &theirs, &pack(&sealed));
    }
    drop_box(relay, &mine);
    println!("session dropped");
}

fn session_slot(a: &str, b: &str, code: &str) -> String {
    let (x, y) = if a < b { (a, b) } else { (b, a) };
    let mut key = [0u8; 16];
    Hkdf::<Sha256>::new(None, code.as_bytes())
    .expand(format!("kestrel slot {x} {y}").as_bytes(), &mut key)
    .expect("hkdf");
    key.iter().map(|b| format!("{b:02x}")).collect()
}

fn prompt(label: &str) -> String {
    eprint!("{label}");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok();
    line.trim().to_string()
}

fn publish(relay: &str, id: &str, wrapped: &[u8]) {
    let mut body = Vec::new();
    body.extend_from_slice(&(id.len() as u16).to_be_bytes());
    body.extend_from_slice(id.as_bytes());
    body.extend_from_slice(wrapped);
    let mut frame = vec![3u8];
    frame.extend_from_slice(&body);
    frame_send(relay, &frame);
}

fn wait_prekey(relay: &str, id: &str, code: &str) -> HybridPublic {
    println!("waiting for the other side");
    for n in 1.. {
        let mut fetch = vec![4u8];
        fetch.extend_from_slice(id.as_bytes());
        let wrapped = frame_send(relay, &fetch);
        if let Ok(raw) = unwrap_prekey(code, &wrapped) {
            if let Ok(public) = HybridPublic::from_bytes(&raw) {
                return public;
            }
        }
        if n % 5 == 0 {
            println!("still waiting, {n}s");
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    unreachable!()
}

fn drop_box(relay: &str, id: &str) {
    let mut frame = vec![5u8];
    frame.extend_from_slice(id.as_bytes());
    frame_send(relay, &frame);
}

fn queue(relay: &str, to: &str, envelope: &[u8]) {
    let mut body = Vec::new();
    body.extend_from_slice(&(to.len() as u16).to_be_bytes());
    body.extend_from_slice(to.as_bytes());
    body.extend_from_slice(envelope);
    let mut put = vec![1u8];
    put.extend_from_slice(&body);
    frame_send(relay, &put);
}

fn print_inbox(secret: &HybridSecret, reply: &[u8], mine: &str) {
    if reply.len() < 4 {
        return;
    }
    let mut rest = &reply[4..];
    while rest.len() >= 4 {
        let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        rest = &rest[4..];
        if rest.len() < n {
            break;
        }
        let (blob, tail) = rest.split_at(n);
        rest = tail;
        match open_envelope(secret, blob) {
            Ok(text) => {
                let text = String::from_utf8_lossy(&text);
                if text != mine {
                    println!("them: {text}");
                }
            }
            Err(_) => println!("blob failed to open"),
        }
    }
}

fn pack(sealed: &SealedMessage) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(sealed.sender.len() as u32).to_be_bytes());
    out.extend_from_slice(&sealed.sender);
    out.extend_from_slice(&sealed.x25519_ephemeral);
    out.extend_from_slice(&(sealed.mlkem_ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&sealed.mlkem_ciphertext);
    out.extend_from_slice(&(sealed.body.len() as u32).to_be_bytes());
    out.extend_from_slice(&sealed.body);
    out.extend_from_slice(&(sealed.signature.len() as u32).to_be_bytes());
    out.extend_from_slice(&sealed.signature);
    out
}

fn open_envelope(secret: &HybridSecret, mut blob: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let sender_len = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
    blob = &blob[4..];
    let sender = PublicIdentity::from_bytes(&blob[..sender_len])?;
    blob = &blob[sender_len..];
    let x25519 = <[u8; 32]>::try_from(&blob[..32]).unwrap();
    blob = &blob[32..];
    let ct_len = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
    blob = &blob[4..];
    let ct = blob[..ct_len].to_vec();
    blob = &blob[ct_len..];
    let body_len = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
    blob = &blob[4..];
    let body = blob[..body_len].to_vec();
    blob = &blob[body_len..];
    let sig_len = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
    blob = &blob[4..];
    let signature = blob[..sig_len].to_vec();
    open_message(
        secret,
        &sender,
        &SealedMessage {
            sender: sender.as_bytes().to_vec(),
                 x25519_ephemeral: x25519,
                 mlkem_ciphertext: ct,
                 body,
                 signature,
        },
    )
}

fn frame_send(relay: &str, payload: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(relay).expect("relay");
    stream.write_all(&(payload.len() as u32).to_be_bytes()).unwrap();
    stream.write_all(payload).unwrap();
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).unwrap();
    let n = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).unwrap();
    buf
}
