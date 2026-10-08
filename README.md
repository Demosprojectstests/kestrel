# Kestrel

A two-person terminal chat. The clients encrypt. The relay only holds the current session.

Each side runs `kestrel chat <me> <them> <host:port>` and types a connection code shared off the app. The session mints an ML-DSA-65 signing key and an X25519 + ML-KEM-768 prekey in memory, wraps the public prekey with that code, and seals lines with XChaCha20-Poly1305. An empty line drops that side's box. Nothing is written to disk. A restarted relay has no history.

## Run

One machine runs the relay:

```bash
./kestreld
