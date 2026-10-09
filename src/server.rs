use crate::common::{self, LatestImage};
use std::io::{Read, Write};
use std::net::TcpListener;

/// Start HTTP server in a background thread.
/// Serves the latest screenshot PNG on GET /clipboard/image.
pub fn start(latest: LatestImage, server_only: bool) -> std::io::Result<()> {
    let addr = format!("127.0.0.1:{}", common::DEFAULT_PORT);
    // Bind before the watcher starts, so a stale daemon/tunnel cannot be mistaken
    // for this process's successfully published clipboard.
    let listener = TcpListener::bind(&addr)?;
    common::log(&format!("http server listening on {addr}"));
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let latest = latest.clone();
            std::thread::spawn(move || handle_request(stream, latest, server_only));
        }
    });
    Ok(())
}

/// `mode` appears only in server-only mode, so `doctor` can explain why local
/// paste gets no file path. Every /health reader matches substrings, so older
/// clients keep accepting the body.
pub(crate) fn health_body(server_only: bool) -> String {
    let mode = if server_only {
        ",\"mode\":\"server-only\""
    } else {
        ""
    };
    format!(
        "{{\"status\":\"ok\",\"version\":\"{}\"{mode}}}",
        common::VERSION
    )
}

fn handle_request(mut stream: std::net::TcpStream, latest: LatestImage, server_only: bool) {
    let mut buf = [0u8; 2048];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    if !host_allowed(&request) {
        respond(&mut stream, 403, "text/plain", b"forbidden host");
        return;
    }
    if first_line.starts_with("GET /health") {
        let body = health_body(server_only);
        respond(&mut stream, 200, "application/json", body.as_bytes());
    } else if first_line.starts_with("GET /clipboard/type") {
        let has_image = latest.lock().ok().and_then(|g| g.clone()).is_some();
        let body = if has_image {
            "{\"type\":\"image\",\"format\":\"png\"}"
        } else {
            "{\"type\":\"empty\"}"
        };
        respond(&mut stream, 200, "application/json", body.as_bytes());
    } else if first_line.starts_with("GET /clipboard/image") {
        let path = latest.lock().ok().and_then(|g| g.clone());
        match path {
            Some(p) => match std::fs::read(&p) {
                Ok(data) => respond(&mut stream, 200, "image/png", &data),
                Err(_) => respond(&mut stream, 404, "text/plain", b"file not found"),
            },
            None => respond(&mut stream, 204, "text/plain", b""),
        }
    } else {
        respond(&mut stream, 404, "text/plain", b"not found");
    }
}

/// Guard against DNS rebinding. A web page can point its own hostname at
/// 127.0.0.1 and then read this server's responses as same-origin, which would
/// expose the user's latest screenshot to any site they visit. Such requests
/// still carry the page's hostname in `Host`, while every legitimate client
/// (curl in the shims, `doctor`, `wsl-setup`) addresses the daemon as
/// `localhost` or by IP address, so only those are answered.
fn host_allowed(request: &str) -> bool {
    let host = request
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("host")
                .then(|| value.trim())
        });
    let Some(host) = host else {
        return false;
    };
    if let Some(rest) = host.strip_prefix('[') {
        return rest
            .split_once(']')
            .is_some_and(|(ip, _)| ip.parse::<std::net::Ipv6Addr>().is_ok());
    }
    let name = host.rsplit_once(':').map_or(host, |(name, _)| name);
    name.eq_ignore_ascii_case("localhost") || name.parse::<std::net::Ipv4Addr>().is_ok()
}

fn respond(stream: &mut std::net::TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let status_text = match status {
        200 => "OK",
        204 => "No Content",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Unknown",
    };
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
}

#[cfg(test)]
mod host_tests {
    use super::*;

    fn request(host_line: &str) -> String {
        format!("GET /clipboard/image HTTP/1.1\r\n{host_line}User-Agent: curl/8.0\r\n\r\n")
    }

    #[test]
    fn answers_loopback_names_and_ip_addresses() {
        for host in [
            "localhost:18340",
            "LOCALHOST",
            "127.0.0.1:18340",
            "172.22.32.1:18340",
            "[::1]:18340",
            "[::1]",
        ] {
            assert!(
                host_allowed(&request(&format!("Host: {host}\r\n"))),
                "{host}"
            );
        }
        assert!(host_allowed(&request("host:localhost:18340\r\n")));
    }

    /// A rebinding page keeps its own hostname in Host even though its DNS
    /// record now points at 127.0.0.1.
    #[test]
    fn rejects_rebound_hostnames_and_missing_host() {
        for host_line in [
            "Host: attacker.example:18340\r\n",
            "Host: localhost.attacker.example\r\n",
            "Host: 127.0.0.1.nip.io:18340\r\n",
            "Host: [not-an-ip]:18340\r\n",
            "Host: \r\n",
            "",
        ] {
            assert!(!host_allowed(&request(host_line)), "{host_line:?}");
        }
    }

    /// Only a header line counts; a Host-looking request target does not.
    #[test]
    fn ignores_host_text_outside_the_headers() {
        let smuggled =
            "GET /Host:localhost HTTP/1.1\r\nHost: evil.example\r\n\r\nHost: localhost\r\n";
        assert!(!host_allowed(smuggled));
    }

    #[test]
    fn forbidden_host_never_reaches_the_clipboard() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client
            .write_all(request("Host: attacker.example:18340\r\n").as_bytes())
            .unwrap();
        handle_request(server, LatestImage::default(), false);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
            "{response}"
        );
    }
}
