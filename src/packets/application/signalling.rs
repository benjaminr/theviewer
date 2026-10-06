//! Where signalling says media will flow: the `m=` and `c=` lines of an SDP
//! body (RFC 8866), as SIP and RTSP carry it, and the client and server
//! ports of an RTSP `Transport` header (RFC 2326 section 12.39).

use std::net::{IpAddr, SocketAddr};

/// Most bytes of a payload searched for signalling.
const MAX_TEXT: usize = 64 * 1024;
/// Most media streams taken from one payload.
const MAX_STREAMS: usize = 16;

/// A UDP endpoint announced for RTP or for its RTCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Announced {
    Rtp(SocketAddr),
    Rtcp(SocketAddr),
}

/// The media endpoints a payload announces, if it holds SDP or an RTSP
/// transport header. `source` and `destination` are the addresses the
/// payload travels between, for SDP without a connection line and for RTSP,
/// which names ports only.
pub fn announced_media(payload: &[u8], source: IpAddr, destination: IpAddr) -> Vec<Announced> {
    let text = &payload[..payload.len().min(MAX_TEXT)];
    // Cheap tests first: most payloads are neither.
    let has_sdp = contains(text, b"\nm=") || text.starts_with(b"m=");
    let has_transport = contains(text, b"client_port=") || contains(text, b"server_port=");
    if !has_sdp && !has_transport {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(text);
    let mut found = Vec::new();
    if has_sdp {
        sdp_media(&text, source, &mut found);
    }
    if has_transport {
        rtsp_transport(&text, source, destination, &mut found);
    }
    found
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// The address of a `c=IN IP4 192.0.2.1` line (a multicast address may
/// carry a "/ttl" suffix).
fn connection_address(value: &str) -> Option<IpAddr> {
    let mut parts = value.split_whitespace();
    let (Some("IN"), Some(_kind), Some(address)) = (parts.next(), parts.next(), parts.next()) else { return None };
    address.split('/').next()?.parse().ok()
}

/// One `m=` line's stream: its port, whether it is RTP, and the RTCP port
/// and connection address its own lines give.
struct MediaLine {
    port: u16,
    address: Option<IpAddr>,
    rtcp_port: Option<u16>,
    rtcp_mux: bool,
}

/// The RTP streams of an SDP body, with their RTCP ports.
fn sdp_media(text: &str, sender: IpAddr, found: &mut Vec<Announced>) {
    let mut session_address = None;
    let mut streams: Vec<MediaLine> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if let Some(value) = line.strip_prefix("c=") {
            match streams.last_mut() {
                Some(stream) => stream.address = connection_address(value).or(stream.address),
                None => session_address = connection_address(value),
            }
        } else if let Some(value) = line.strip_prefix("m=") {
            if streams.len() == MAX_STREAMS {
                break;
            }
            let mut parts = value.split_whitespace();
            let (Some(_media), Some(port), Some(protocol)) = (parts.next(), parts.next(), parts.next()) else { continue };
            let Ok(port) = port.split('/').next().unwrap_or_default().parse::<u16>() else { continue };
            if port != 0 && protocol.contains("RTP") {
                streams.push(MediaLine { port, address: None, rtcp_port: None, rtcp_mux: false });
            }
        } else if let Some(stream) = streams.last_mut() {
            if let Some(value) = line.strip_prefix("a=rtcp:") {
                stream.rtcp_port = value.split_whitespace().next().and_then(|port| port.parse().ok());
            } else if line == "a=rtcp-mux" {
                stream.rtcp_mux = true;
            }
        }
    }
    for stream in streams {
        let address = stream.address.or(session_address).unwrap_or(sender);
        found.push(Announced::Rtp(SocketAddr::new(address, stream.port)));
        if !stream.rtcp_mux {
            let rtcp_port = stream.rtcp_port.unwrap_or(stream.port.wrapping_add(1));
            found.push(Announced::Rtcp(SocketAddr::new(address, rtcp_port)));
        }
    }
}

/// A port pair such as "4588-4589", or a single port.
fn port_pair(value: &str) -> Option<(u16, Option<u16>)> {
    let mut parts = value.split('-');
    let first = parts.next()?.trim().parse().ok()?;
    let second = parts.next().and_then(|port| port.trim().parse().ok());
    Some((first, second))
}

/// The ports of an RTSP `Transport` header. A request travels from the
/// client; a response ("RTSP/1.0 200 OK") to it.
fn rtsp_transport(text: &str, source: IpAddr, destination: IpAddr, found: &mut Vec<Announced>) {
    let is_response = text.starts_with("RTSP/");
    let (client, server) = if is_response { (destination, source) } else { (source, destination) };
    for line in text.lines().filter(|line| line.get(..10).is_some_and(|name| name.eq_ignore_ascii_case("transport:"))) {
        // Media interleaved in the RTSP connection itself has no UDP ports.
        if !line.contains("RTP") || line.contains("/TCP") {
            continue;
        }
        for parameter in line[10..].split([';', ',']) {
            let (address, value) = match parameter.trim().split_once('=') {
                Some(("client_port", value)) => (client, value),
                Some(("server_port", value)) => (server, value),
                _ => continue,
            };
            let Some((rtp, rtcp)) = port_pair(value) else { continue };
            found.push(Announced::Rtp(SocketAddr::new(address, rtp)));
            if let Some(rtcp) = rtcp {
                found.push(Announced::Rtcp(SocketAddr::new(address, rtcp)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALLER: [u8; 4] = [192, 0, 2, 10];
    const CALLEE: [u8; 4] = [192, 0, 2, 20];

    fn rtp(address: [u8; 4], port: u16) -> Announced {
        Announced::Rtp(SocketAddr::new(IpAddr::from(address), port))
    }

    fn rtcp(address: [u8; 4], port: u16) -> Announced {
        Announced::Rtcp(SocketAddr::new(IpAddr::from(address), port))
    }

    #[test]
    fn a_sip_invite_announces_its_rtp_stream_and_the_rtcp_port_above_it() {
        let invite = "INVITE sip:bob@example.com SIP/2.0\r\nContent-Type: application/sdp\r\n\r\nv=0\r\no=- 1 1 IN IP4 192.0.2.10\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\nm=audio 49170 RTP/AVP 0 8\r\nm=video 0 RTP/AVP 31\r\n";
        let found = announced_media(invite.as_bytes(), IpAddr::from(CALLER), IpAddr::from(CALLEE));
        assert_eq!(found, [rtp([198, 51, 100, 7], 49170), rtcp([198, 51, 100, 7], 49171)], "a port of 0 is a refused stream");
    }

    #[test]
    fn media_level_addresses_rtcp_attributes_and_multiplexing_are_honoured() {
        let sdp = "v=0\r\nm=audio 5004 RTP/SAVPF 111\r\nc=IN IP4 203.0.113.1/127\r\na=rtcp:5010\r\nm=video 5006 RTP/AVP 96\r\na=rtcp-mux\r\nm=application 9 UDP/DTLS/SCTP webrtc\r\n";
        let found = announced_media(format!("x\n{sdp}").as_bytes(), IpAddr::from(CALLER), IpAddr::from(CALLEE));
        assert_eq!(found, [rtp([203, 0, 113, 1], 5004), rtcp([203, 0, 113, 1], 5010), rtp(CALLER, 5006)]);
    }

    #[test]
    fn an_rtsp_setup_reply_names_the_client_and_server_ports() {
        let reply = "RTSP/1.0 200 OK\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=4588-4589;server_port=6256-6257\r\n\r\n";
        let found = announced_media(reply.as_bytes(), IpAddr::from(CALLEE), IpAddr::from(CALLER));
        assert_eq!(found, [rtp(CALLER, 4588), rtcp(CALLER, 4589), rtp(CALLEE, 6256), rtcp(CALLEE, 6257)]);
        let interleaved = "RTSP/1.0 200 OK\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;client_port=1-2\r\n\r\n";
        assert!(announced_media(interleaved.as_bytes(), IpAddr::from(CALLEE), IpAddr::from(CALLER)).is_empty());
    }

    #[test]
    fn other_payloads_announce_nothing() {
        assert!(announced_media(b"GET / HTTP/1.1\r\n\r\n", IpAddr::from(CALLER), IpAddr::from(CALLEE)).is_empty());
        assert!(announced_media(b"\nm=audio notaport RTP/AVP 0\n", IpAddr::from(CALLER), IpAddr::from(CALLEE)).is_empty());
        assert!(announced_media(&[0xFF, b'\n', b'm', b'=', 0xC3], IpAddr::from(CALLER), IpAddr::from(CALLEE)).is_empty());
    }
}
