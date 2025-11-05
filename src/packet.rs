use chrono::{DateTime, Utc};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: DateTime<Utc>,
    pub length: usize,
    pub captured_length: usize,
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
    pub fn new(length: usize, captured_length: usize) -> Self {
        Self {
            timestamp: Utc::now(),
            length,
            captured_length,
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

    pub fn matches_filter(&self, filter: &str) -> bool {
        // Simple filter matching - can be enhanced
        if filter.is_empty() {
            return false;
        }
        
        let filter_lower = filter.to_lowercase();
        
        // Check IP addresses
        if let Some(ip) = self.get_ip_layer() {
            // Check TCP port filter - cache TCP layer to avoid multiple lookups
            if filter_lower.contains("tcp") && filter_lower.contains("port") {
                if let Some(tcp) = self.get_tcp_layer() {
                    if let Some(port_str) = filter_lower.split("port").nth(1) {
                        let port_str = port_str.trim();
                        if !port_str.is_empty() {
                            if let Ok(port) = port_str.parse::<u16>() {
                                if tcp.src_port == port || tcp.dst_port == port {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            
            // Check UDP port filter - cache UDP layer to avoid multiple lookups
            if filter_lower.contains("udp") && filter_lower.contains("port") {
                if let Some(udp) = self.get_udp_layer() {
                    if let Some(port_str) = filter_lower.split("port").nth(1) {
                        let port_str = port_str.trim();
                        if !port_str.is_empty() {
                            if let Ok(port) = port_str.parse::<u16>() {
                                if udp.src_port == port || udp.dst_port == port {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            
            // Check for protocol-only filters (without port)
            if filter_lower == "tcp" && self.get_tcp_layer().is_some() {
                return true;
            }
            if filter_lower == "udp" && self.get_udp_layer().is_some() {
                return true;
            }
            if filter_lower == "icmp" && self.get_icmp_layer().is_some() {
                return true;
            }
            
            // Check source IP filter (must be word boundary or start of string)
            if filter_lower.contains("src") {
                // More precise matching: "src" followed by space or end
                let parts: Vec<&str> = filter_lower.split_whitespace().collect();
                for (i, part) in parts.iter().enumerate() {
                    if part == &"src" && i + 1 < parts.len() {
                        let ip_str = parts[i + 1].trim();
                        if !ip_str.is_empty() {
                            if ip.src_ip.to_string().contains(ip_str) {
                                return true;
                            }
                        }
                    }
                }
            }
            
            // Check destination IP filter
            if filter_lower.contains("dst") {
                let parts: Vec<&str> = filter_lower.split_whitespace().collect();
                for (i, part) in parts.iter().enumerate() {
                    if part == &"dst" && i + 1 < parts.len() {
                        let ip_str = parts[i + 1].trim();
                        if !ip_str.is_empty() {
                            if ip.dst_ip.to_string().contains(ip_str) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        
        false
    }
}
