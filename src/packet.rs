use chrono::{DateTime, Utc};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: DateTime<Utc>,
    pub length: usize,
    pub captured_length: usize,
    pub raw_data: Vec<u8>,
    pub layers: Vec<Layer>,
}

#[derive(Debug, Clone)]
pub enum Layer {
    Ethernet(EthernetLayer),
    Ip(IpLayer),
    Tcp(TcpLayer),
    Udp(UdpLayer),
    Icmp(IcmpLayer),
    Http(HttpLayer),
    Dns(DnsLayer),
    Arp(ArpLayer),
    Ssl(SslLayer),
    Unknown(String),
}

#[derive(Debug, Clone)]
pub struct EthernetLayer {
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: u16,
}

#[derive(Debug, Clone)]
pub struct IpLayer {
    pub version: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: u8,
    pub ttl: u8,
    pub total_length: u16,
}

#[derive(Debug, Clone)]
pub struct TcpLayer {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub data_offset: u8,
}

#[derive(Debug, Clone)]
pub struct UdpLayer {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone)]
pub struct IcmpLayer {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
}

#[derive(Debug, Clone)]
pub struct HttpLayer {
    pub is_request: bool,
    pub method: Option<String>,
    pub path: Option<String>,
    pub version: Option<String>,
    pub status_code: Option<u16>,
    pub status_message: Option<String>,
    pub headers: Vec<(String, String)>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DnsLayer {
    pub is_response: bool,
    pub transaction_id: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ArpLayer {
    pub operation: u16,
    pub src_mac: String,
    pub src_ip: IpAddr,
    pub dst_mac: String,
    pub dst_ip: IpAddr,
}

#[derive(Debug, Clone)]
pub struct SslLayer {
    pub content_type: u8,
    pub version: String,
    pub length: u16,
    pub handshake_type: Option<u8>, // For handshake messages
}

#[derive(Debug, Clone)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub fn to_string(&self) -> String {
        let mut flags = Vec::new();
        if self.fin { flags.push("FIN"); }
        if self.syn { flags.push("SYN"); }
        if self.rst { flags.push("RST"); }
        if self.psh { flags.push("PSH"); }
        if self.ack { flags.push("ACK"); }
        if self.urg { flags.push("URG"); }
        flags.join(",")
    }
}

impl Packet {
    pub fn new(length: usize, captured_length: usize, raw_data: Vec<u8>) -> Self {
        Self {
            timestamp: Utc::now(),
            length,
            captured_length,
            raw_data,
            layers: Vec::new(),
        }
    }

    pub fn get_ethertype(&self) -> Option<u16> {
        for layer in &self.layers {
            if let Layer::Ethernet(eth) = layer {
                return Some(eth.ethertype);
            }
        }
        None
    }

    pub fn get_ip_layer(&self) -> Option<&IpLayer> {
        for layer in &self.layers {
            if let Layer::Ip(ip) = layer {
                return Some(ip);
            }
        }
        None
    }

    pub fn get_tcp_layer(&self) -> Option<&TcpLayer> {
        for layer in &self.layers {
            if let Layer::Tcp(tcp) = layer {
                return Some(tcp);
            }
        }
        None
    }

    pub fn get_udp_layer(&self) -> Option<&UdpLayer> {
        for layer in &self.layers {
            if let Layer::Udp(udp) = layer {
                return Some(udp);
            }
        }
        None
    }

    pub fn get_icmp_layer(&self) -> Option<&IcmpLayer> {
        for layer in &self.layers {
            if let Layer::Icmp(icmp) = layer {
                return Some(icmp);
            }
        }
        None
    }

    pub fn get_http_layer(&self) -> Option<&HttpLayer> {
        for layer in &self.layers {
            if let Layer::Http(http) = layer {
                return Some(http);
            }
        }
        None
    }

    pub fn get_dns_layer(&self) -> Option<&DnsLayer> {
        for layer in &self.layers {
            if let Layer::Dns(dns) = layer {
                return Some(dns);
            }
        }
        None
    }

    pub fn get_arp_layer(&self) -> Option<&ArpLayer> {
        for layer in &self.layers {
            if let Layer::Arp(arp) = layer {
                return Some(arp);
            }
        }
        None
    }

    pub fn get_ssl_layer(&self) -> Option<&SslLayer> {
        for layer in &self.layers {
            if let Layer::Ssl(ssl) = layer {
                return Some(ssl);
            }
        }
        None
    }

    pub fn matches_filter(&self, filter: &str) -> bool {
        if filter.trim().is_empty() {
            return true; // Empty filter matches all
        }

        // Parse and evaluate the filter expression
        match self.parse_filter_expression(filter) {
            Ok(result) => result,
            Err(_) => false, // If parsing fails, don't match
        }
    }

    fn parse_filter_expression(&self, expr: &str) -> Result<bool, ()> {
        // Simple recursive descent parser for filter expressions
        // Supports: AND, OR, NOT, parentheses, basic terms

        let expr = expr.trim();
        if expr.is_empty() {
            return Ok(true);
        }

        // Handle parentheses
        if expr.starts_with('(') && expr.ends_with(')') {
            return self.parse_filter_expression(&expr[1..expr.len()-1]);
        }

        // Handle NOT
        if expr.to_lowercase().starts_with("not ") {
            let rest = &expr[4..];
            return self.parse_filter_expression(rest).map(|r| !r);
        }

        // Split on OR (lowest precedence)
        if let Some(or_pos) = Self::find_operator(expr, "or") {
            let left = &expr[..or_pos];
            let right = &expr[or_pos + 2..];
            let left_result = self.parse_filter_expression(left)?;
            let right_result = self.parse_filter_expression(right)?;
            return Ok(left_result || right_result);
        }

        // Split on AND
        if let Some(and_pos) = Self::find_operator(expr, "and") {
            let left = &expr[..and_pos];
            let right = &expr[and_pos + 3..];
            let left_result = self.parse_filter_expression(left)?;
            let right_result = self.parse_filter_expression(right)?;
            return Ok(left_result && right_result);
        }

        // Base case: evaluate single term
        Ok(self.evaluate_filter_term(expr.trim()))
    }

    fn find_operator(expr: &str, op: &str) -> Option<usize> {
        let mut paren_depth = 0;
        let expr_lower = expr.to_lowercase();
        let op_lower = op.to_lowercase();

        for (i, _) in expr.char_indices() {
            let slice = &expr_lower[i..];
            if slice.starts_with('(') {
                paren_depth += 1;
            } else if slice.starts_with(')') {
                paren_depth -= 1;
            } else if paren_depth == 0 && slice.starts_with(&op_lower) {
                // Check if it's a word boundary
                let before = if i > 0 { &expr[i-1..i] } else { "" };
                let after = if i + op.len() < expr.len() { &expr[i + op.len()..i + op.len() + 1] } else { "" };
                if (before.is_empty() || before.chars().all(|c| !c.is_alphanumeric())) &&
                   (after.is_empty() || after.chars().all(|c| !c.is_alphanumeric())) {
                    return Some(i);
                }
            }
        }
        None
    }

    fn evaluate_filter_term(&self, term: &str) -> bool {
        let term_lower = term.to_lowercase();
        let parts: Vec<&str> = term_lower.split_whitespace().collect();

        if parts.is_empty() {
            return false;
        }

        // Port filters: "tcp port 80", "udp port 53"
        if parts.len() >= 3 && parts[1] == "port" {
            if let Ok(port) = parts[2].parse::<u16>() {
                match parts[0] {
                    "tcp" => {
                        if let Some(tcp) = self.get_tcp_layer() {
                            return tcp.src_port == port || tcp.dst_port == port;
                        }
                    }
                    "udp" => {
                        if let Some(udp) = self.get_udp_layer() {
                            return udp.src_port == port || udp.dst_port == port;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Protocol-only filters
        match parts[0] {
            "tcp" => return self.get_tcp_layer().is_some(),
            "udp" => return self.get_udp_layer().is_some(),
            "icmp" => return self.get_icmp_layer().is_some(),
            "arp" => return self.get_arp_layer().is_some(),
            "http" => return self.get_http_layer().is_some(),
            "dns" => return self.get_dns_layer().is_some(),
            _ => {}
        }

        // IP address filters: "src 192.168.1.1", "dst 10.0.0.1", "host 8.8.8.8"
        if let Some(ip) = self.get_ip_layer() {
            if parts.len() >= 2 {
                let ip_str = parts[1];
                match parts[0] {
                    "src" => return ip.src_ip.to_string().contains(ip_str),
                    "dst" => return ip.dst_ip.to_string().contains(ip_str),
                    "host" => return ip.src_ip.to_string().contains(ip_str) || ip.dst_ip.to_string().contains(ip_str),
                    _ => {}
                }
            }
        }

        // ARP IP filters
        if let Some(arp) = self.get_arp_layer() {
            if parts.len() >= 2 {
                let ip_str = parts[1];
                match parts[0] {
                    "src" => return arp.src_ip.to_string().contains(ip_str),
                    "dst" => return arp.dst_ip.to_string().contains(ip_str),
                    "host" => return arp.src_ip.to_string().contains(ip_str) || arp.dst_ip.to_string().contains(ip_str),
                    _ => {}
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_packet_with_tcp(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Packet {
        let mut packet = Packet::new(64, 64, vec![0; 64]);
        packet.layers.push(Layer::Ip(IpLayer {
            version: 4,
            src_ip: src_ip.parse().unwrap(),
            dst_ip: dst_ip.parse().unwrap(),
            protocol: 6, // TCP
            ttl: 64,
            total_length: 64,
        }));
        packet.layers.push(Layer::Tcp(TcpLayer {
            src_port,
            dst_port,
            seq: 1000,
            ack: 2000,
            flags: TcpFlags { fin: false, syn: true, rst: false, psh: false, ack: false, urg: false },
            window: 65535,
            data_offset: 5,
        }));
        packet
    }

    fn create_test_packet_with_udp(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Packet {
        let mut packet = Packet::new(64, 64, vec![0; 64]);
        packet.layers.push(Layer::Ip(IpLayer {
            version: 4,
            src_ip: src_ip.parse().unwrap(),
            dst_ip: dst_ip.parse().unwrap(),
            protocol: 17, // UDP
            ttl: 64,
            total_length: 64,
        }));
        packet.layers.push(Layer::Udp(UdpLayer {
            src_port,
            dst_port,
            length: 32,
            checksum: 0,
        }));
        packet
    }

    #[test]
    fn test_matches_filter_empty() {
        let packet = create_test_packet_with_tcp("192.168.1.1", "10.0.0.1", 12345, 80);
        assert!(packet.matches_filter(""));
        assert!(packet.matches_filter("   "));
    }

    #[test]
    fn test_matches_filter_tcp() {
        let packet = create_test_packet_with_tcp("192.168.1.1", "10.0.0.1", 12345, 80);
        assert!(packet.matches_filter("tcp"));
        assert!(!packet.matches_filter("udp"));
    }

    #[test]
    fn test_matches_filter_tcp_port() {
        let packet = create_test_packet_with_tcp("192.168.1.1", "10.0.0.1", 12345, 80);
        assert!(packet.matches_filter("tcp port 80"));
        assert!(packet.matches_filter("tcp port 12345"));
        assert!(!packet.matches_filter("tcp port 443"));
    }

    #[test]
    fn test_matches_filter_udp_port() {
        let packet = create_test_packet_with_udp("192.168.1.1", "8.8.8.8", 12345, 53);
        assert!(packet.matches_filter("udp port 53"));
        assert!(packet.matches_filter("udp port 12345"));
        assert!(!packet.matches_filter("tcp port 53"));
    }

    #[test]
    fn test_matches_filter_src_ip() {
        let packet = create_test_packet_with_tcp("192.168.1.1", "10.0.0.1", 12345, 80);
        assert!(packet.matches_filter("src 192.168.1.1"));
        assert!(packet.matches_filter("src 192.168"));
        assert!(!packet.matches_filter("src 10.0.0.1"));
    }

    #[test]
    fn test_matches_filter_dst_ip() {
        let packet = create_test_packet_with_tcp("192.168.1.1", "10.0.0.1", 12345, 80);
        assert!(packet.matches_filter("dst 10.0.0.1"));
        assert!(!packet.matches_filter("dst 192.168.1.1"));
    }

    #[test]
    fn test_matches_filter_host() {
        let packet = create_test_packet_with_tcp("192.168.1.1", "10.0.0.1", 12345, 80);
        assert!(packet.matches_filter("host 192.168.1.1"));
        assert!(packet.matches_filter("host 10.0.0.1"));
        assert!(!packet.matches_filter("host 8.8.8.8"));
    }

    #[test]
    fn test_matches_filter_and() {
        let packet = create_test_packet_with_tcp("192.168.1.1", "10.0.0.1", 12345, 80);
        assert!(packet.matches_filter("tcp and src 192.168.1.1"));
        assert!(packet.matches_filter("tcp port 80 and dst 10.0.0.1"));
        assert!(!packet.matches_filter("tcp and src 10.0.0.1"));
    }

    #[test]
    fn test_matches_filter_or() {
        let packet = create_test_packet_with_tcp("192.168.1.1", "10.0.0.1", 12345, 80);
        assert!(packet.matches_filter("tcp port 80 or udp port 53"));
        assert!(packet.matches_filter("src 192.168.1.1 or src 10.0.0.1"));
        assert!(!packet.matches_filter("tcp port 443 or udp port 53"));
    }

    #[test]
    fn test_matches_filter_not() {
        let packet = create_test_packet_with_tcp("192.168.1.1", "10.0.0.1", 12345, 80);
        assert!(packet.matches_filter("not udp"));
        assert!(!packet.matches_filter("not tcp"));
    }

    #[test]
    fn test_matches_filter_parentheses() {
        let packet = create_test_packet_with_tcp("192.168.1.1", "10.0.0.1", 12345, 80);
        assert!(packet.matches_filter("(tcp)"));
        assert!(packet.matches_filter("(tcp and src 192.168.1.1)"));
        assert!(packet.matches_filter("tcp and (src 192.168.1.1 or dst 10.0.0.1)"));
    }

    #[test]
    fn test_matches_filter_complex() {
        let packet = create_test_packet_with_tcp("192.168.1.1", "10.0.0.1", 12345, 80);
        assert!(packet.matches_filter("tcp port 80 and src 192.168.1.1 and dst 10.0.0.1"));
        assert!(!packet.matches_filter("tcp port 443 and src 192.168.1.1"));
    }
}
