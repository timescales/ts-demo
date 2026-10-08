//! A minimal HTTP/1.1 client over a TCP stream, for the stub server and the
//! recorder. reqwest cannot be built in this crate's tests: it is compiled
//! with `rustls-no-provider`, and nothing here may install a rustls provider.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Timeout,
    Transport(String),
}

/// POSTs a JSON `body` to an `http://host:port/path` URL and returns the
/// status and body.
pub async fn post(url: &str, body: &[u8], timeout: Duration) -> Result<(u16, Vec<u8>), Error> {
    tokio::time::timeout(timeout, exchange(url, body))
        .await
        .map_err(|_| Error::Timeout)?
}

async fn exchange(url: &str, body: &[u8]) -> Result<(u16, Vec<u8>), Error> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| Error::Transport(format!("not an http URL: {url}")))?;
    let (host, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_owned()), |(h, p)| (h, format!("/{p}")));
    let mut stream = TcpStream::connect(host)
        .await
        .map_err(|e| Error::Transport(e.to_string()))?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|e| Error::Transport(e.to_string()))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| Error::Transport(e.to_string()))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| Error::Transport(e.to_string()))?;
    parse(&response)
}

fn parse(response: &[u8]) -> Result<(u16, Vec<u8>), Error> {
    let bad = |what: &str| Error::Transport(format!("malformed HTTP response: {what}"));
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| bad("no header end"))?;
    let head = std::str::from_utf8(&response[..split]).map_err(|_| bad("header is not UTF-8"))?;
    let body = &response[split + 4..];
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad("status line"))?;
    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    let body = if chunked {
        dechunk(body).ok_or_else(|| bad("chunks"))?
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n")?;
        let size = usize::from_str_radix(std::str::from_utf8(&b[..eol]).ok()?.trim(), 16).ok()?;
        b = &b[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(b.get(..size)?);
        b = b.get(size + 2..)?;
    }
}
