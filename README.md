# Kuwo Music Relay Decrypt Server

[English](README.md) | [中文](README_CN.md)

A single-file PHP relay server that decrypts Kuwo Music encrypted audio files (`.mflac`, `.mgg`, `.mmp3`) in real-time and streams them to media players. Designed for use with LX Music and other players that accept URL-based playback.

## Features

- **Real-time streaming decryption** — playback starts before the full file is downloaded
- **Multi-format support** — `.mflac` (FLAC), `.mgg` (OGG Vorbis), `.mmp3` (MP3)
- **HTTP Range support** — seeking works by forwarding range requests to the CDN
- **Disk caching** — decrypted files are cached for repeat access; partial cache resume on disconnect
- **Concurrent request handling** — file locking prevents duplicate downloads of the same song
- **FLAC metadata extraction** — sends `X-Duration`, `X-Sample-Rate`, `X-Channels`, `X-Bits-Per-Sample` headers
- **CORS support** — browser-based players can access the server cross-origin
- **SSRF protection** — blocks requests to private/reserved IP ranges
- **Third-party player compatible** — works with LX Music and other URL-based players
- **Single file deployment** — just upload `decrypt.php` to any PHP server

## Requirements

- PHP 7.4+ (64-bit)
- cURL extension

## Quick Start

### Option 1: Docker (recommended)

```bash
# Using docker-compose
docker compose up -d

# Or build manually
docker build -t kuwo-relay .
docker run -d -p 8080:8080 --name kuwo-relay kuwo-relay
```

Then open `http://localhost:8080/` in your browser.

### Option 2: PHP built-in server

```bash
php -S 0.0.0.0:8080 decrypt.php
```

### Option 3: Upload to a web server

1. Upload `decrypt.php` to your PHP-enabled web server (Apache/Nginx + PHP-FPM)
2. Ensure the web server can write to the system temp directory (`/tmp/mflac_relay/`)
3. Access it via browser to see the help page

## Usage

### Basic URL format

```
http://your-server/decrypt.php?url=<encrypted_file_url>&ekey=<encryption_key>
```

### With LX Music

Configure your LX Music custom source plugin to point to this server. The plugin constructs URLs with `url` and `ekey` parameters — you must deploy this server yourself and fill in its address in the plugin configuration (see [lx-music-xinghai-source](https://github.com/cdyUuu/lx-music-xinghai-source) for details).

### Download mode

Append `&download=1` to force download instead of inline playback:

```
http://your-server/decrypt.php?url=<url>&ekey=<key>&download=1
```

## Configuration

All settings are defined as PHP constants at the top of `decrypt.php`:

| Constant | Default | Description |
|----------|---------|-------------|
| `RELAY_CACHE_DIR` | `/tmp/mflac_relay` | Cache directory for decrypted files |
| `RELAY_LOG_FILE` | `./access.log` | Log file path (relative to script) |
| `RELAY_ENABLE_LOG` | `true` | Enable/disable logging |
| `RELAY_CACHE_TIME` | `3600` | Cache TTL in seconds (1 hour) |
| `RELAY_DOWNLOAD_TIMEOUT` | `300` | Download timeout in seconds |
| `RELAY_CONNECT_TIMEOUT` | `15` | Connection timeout in seconds |
| `RELAY_MAX_CACHE_SIZE` | `536870912` | Max total cache size in bytes (512MB) |
| `RELAY_MAX_CACHE_FILES` | `50` | Max number of cached files |
| `RELAY_MAX_LOG_SIZE` | `10485760` | Max log file size before rotation (10MB) |
| `RELAY_MEMORY_LIMIT` | `256M` | PHP memory limit |
| `RELAY_VERSION` | `1.0.0` | Server version |

## How It Works

```
Player  <──decrypted audio──>  decrypt.php  <──encrypted data──>  Kuwo CDN
                                    |
                              decrypt + cache
                              to disk
```

1. **Player sends HEAD** → server returns `Content-Type`, `Content-Length`, `Accept-Ranges: bytes`
2. **Player sends GET** → server starts downloading from CDN, decrypting in real-time, streaming to player + caching to disk
3. **Player seeks (Range request)** → server forwards the byte range to CDN, decrypts only that range, returns `206 Partial Content`
4. **Player replays same song** → server serves from disk cache instantly

### Decryption Algorithm

The decryption uses the QMC2 encryption scheme:

1. **ekey decryption**: The `ekey` is Base64-encoded and encrypted with TC-TEA (Tencent TEA). After decryption, a raw key is extracted.
2. **Key derivation**: The raw key is processed through QMC key derivation (EncV2 format detection, hash computation).
3. **Audio decryption**: Based on key length:
   - Key <= 300 bytes → **Map XOR cipher** (position-based key mapping)
   - Key > 300 bytes → **RC4 stream cipher** with segment-based skip logic

### About MGG Audio Quality Display

QQ Music's `.mgg` files are encoded as 4-channel OGG Vorbis at 640kbps nominal bitrate (equivalent to 320kbps stereo duplicated across 4 channels). This is the original encoding from QQ Music's CDN — the decryption is correct, but some players may display this as "high quality" or "master" due to the 640kbps bitrate in the OGG header. This is expected behavior and cannot be changed without modifying the audio data.

## Supported Formats

| Extension | Decrypted Format | Content-Type |
|-----------|-----------------|--------------|
| `.mflac` / `.mflac0` | FLAC | `audio/flac` |
| `.mgg` / `.mggl` | OGG Vorbis | `audio/ogg` |
| `.mmp3` | MP3 | `audio/mpeg` |

## Logging

Logs are written as single-line JSON to `access.log` (configurable). Each entry includes:

- Timestamp, log level, client IP, HTTP method
- Request URI, ekey prefix (first 16 chars), Range header, User-Agent
- Download/decrypt byte counts, completion percentage, timing

Log rotation: when the log file exceeds `RELAY_MAX_LOG_SIZE`, the current file is renamed to `.old` and a new file is started.

## Security

- **URL scheme validation** — only `http`/`https` allowed
- **SSRF protection** — blocks requests targeting private/reserved IP ranges (RFC 1918, loopback, link-local)
- **ekey length validation** — rejects malformed keys
- **No file path traversal** — cache keys are SHA-256 hashes
- **Cache files** stored in system temp directory with restrictive permissions

## Project Structure

```
.
├── decrypt.php         # Main server (single file, ~2200 lines)
├── Dockerfile          # Docker image definition
├── docker-compose.yml  # Docker Compose configuration
├── README.md           # English documentation
├── README_CN.md        # Chinese documentation
├── LICENSE             # PolyForm Noncommercial
└── .gitignore          # Git ignore rules
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Guidelines

- Keep the single-file architecture — all server logic should remain in `decrypt.php`
- Test with actual `.mflac` and `.mgg` files before submitting
- Update the README if you add new configuration options
- Follow the existing code style (PSR-12 compatible)

## Algorithm Reference

The DES implementation is based on the federal standard [FIPS PUB 46-3](https://csrc.nist.gov/publications/detail/fips/46/3/archive/1999-10-25) (Data Encryption Standard). The QMC encryption scheme was reverse-engineered for interoperability purposes.

## Disclaimer

This project is intended for **personal study and technical research purposes only**.

- This project does not host, store, or distribute any copyrighted audio files.
- Users must obtain the necessary permissions or licenses from the copyright holders before using this tool.
- The authors and contributors of this project are not responsible for any legal consequences arising from the use of this tool.
- By using this project, you agree to bear all legal responsibilities for your actions.
- If you are a copyright holder and believe this project infringes your rights, please contact the repository owner for removal.
- Commercial use, redistribution of decrypted content, and any form of profit-making from this tool are strictly prohibited.

## Compatible LX Music Plugin

This server is designed to work with the LX Music custom source plugin:
[lx-music-xinghai-source](https://github.com/cdyUuu/lx-music-xinghai-source)

**You must deploy this server yourself.** The plugin does not connect to any
server by default — you need to fill in your server address in the plugin's
`KW_DECRYPT_PROXY` configuration. Once configured, the plugin routes Kuwo
encrypted audio (`.mflac` / `.mgg`) through your relay server for real-time
decryption. **Please use the above plugin as the canonical source for
compatibility.**

## License

PolyForm Noncommercial License 1.0.0 — see [LICENSE](LICENSE) for details.

This project uses the [PolyForm Noncommercial License](https://polyformproject.org/licenses/noncommercial/1.0.0),
which **prohibits commercial use**. Commercial use includes selling the software,
using it in paid services, distributing decrypted content for profit, or
integrating it into commercial products. Personal study, technical research, and
non-commercial educational use are permitted.
