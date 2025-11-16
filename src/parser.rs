use crate::packet::*;
use byteorder::{BigEndian, ByteOrder};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct PacketParser;

impl PacketParser {
    pub fn parse(data: &[u8]) -> anyhow::Result<Packet> {
        let mut packet = Packet::new(data.len(), data.len(), data.to_vec());
        
        if data.len() < 14 {
            return Err(anyhow::anyhow!("Packet too short for Ethernet header"));
        }

        // Parse Ethernet header
        let ethernet = Self::parse_ethernet(&data[0..14])?;
        packet.layers.push(Layer::Ethernet(ethernet.clone()));

        // Parse ARP if present
        if ethernet.ethertype == 0x0806 {
            // ARP packet: 14 bytes Ethernet + 28 bytes ARP = 42 bytes minimum
            if data.len() >= 42 {
                if let Ok(arp) = Self::parse_arp(&data[14..]) {
                    packet.layers.push(Layer::Arp(arp));
                }
            }
            // Return even if ARP parsing failed - we still have Ethernet layer
            return Ok(packet);
        }

        // Parse IP layer if present
        if ethernet.ethertype == 0x0800 || ethernet.ethertype == 0x86DD {
            if data.len() >= 34 {
                match ethernet.ethertype {
                    0x0800 => {
                        // IPv4
                        if let Ok(ip_layer) = Self::parse_ipv4(&data[14..]) {
                            packet.layers.push(Layer::Ip(ip_layer.clone()));
                            
                            // Parse transport layer
                            if let Ok(transport) = Self::parse_transport(&ip_layer, &data[14..]) {
                                let transport_clone = transport.clone();
                                packet.layers.push(transport.clone());
                                
                                // Parse application layer protocols
                                // Calculate IP header length (minimum 20 bytes, can be longer with options)
                                let ip_header_len = {
                                    let ihl = (data[14] & 0x0F) as usize;
                                    if ihl < 5 || ihl > 15 {
                                        // Skip application parsing if header invalid
                                        // (header_len is already validated in parse_ipv4)
                                        0
                                    } else {
                                        ihl * 4
                                    }
                                };
                                
                                // Ensure we have enough data for the transport layer + application
                                if ip_header_len > 0 && data.len() >= 14 + ip_header_len {
                                    let transport_data = &data[14 + ip_header_len..];
                                    // Only try to parse if we have data beyond transport header
                                    if !transport_data.is_empty() {
                                        if let Ok(app_layer) = Self::parse_application(&transport_clone, transport_data) {
                                            packet.layers.push(app_layer);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    0x86DD => {
                        // IPv6 (basic support)
                        if let Ok(ip_layer) = Self::parse_ipv6(&data[14..]) {
                            packet.layers.push(Layer::Ip(ip_layer));
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(packet)
    }

    fn parse_ethernet(data: &[u8]) -> anyhow::Result<EthernetLayer> {
        if data.len() < 14 {
            return Err(anyhow::anyhow!("Ethernet header too short"));
        }

        let dst_mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            data[0], data[1], data[2], data[3], data[4], data[5]
        );
        let src_mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            data[6], data[7], data[8], data[9], data[10], data[11]
        );
        let ethertype = BigEndian::read_u16(&data[12..14]);

        Ok(EthernetLayer {
            src_mac,
            dst_mac,
            ethertype,
        })
    }

    fn parse_ipv4(data: &[u8]) -> anyhow::Result<IpLayer> {
        if data.len() < 20 {
            return Err(anyhow::anyhow!("IPv4 header too short"));
        }

        let version = (data[0] >> 4) & 0x0F;
        
        if version != 4 {
            return Err(anyhow::anyhow!("Not IPv4"));
        }

        // Calculate header length (minimum 20 bytes, can be up to 60 bytes with options)
        let ihl = (data[0] & 0x0F) as usize;
        let header_len = ihl * 4;
        
        // IHL must be at least 5 (20 bytes) and at most 15 (60 bytes)
        if ihl < 5 || ihl > 15 || header_len > 60 || data.len() < header_len {
            return Err(anyhow::anyhow!("Invalid IPv4 header length"));
        }

        // Ensure we have enough data for required fields (minimum 20 bytes)
        if data.len() < 20 {
            return Err(anyhow::anyhow!("IPv4 header incomplete"));
        }

        let protocol = data[9];
        let ttl = data[8];
        let total_length = BigEndian::read_u16(&data[2..4]);

        let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        Ok(IpLayer {
            version,
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(dst_ip),
            protocol,
            ttl,
            total_length,
        })
    }

    fn parse_ipv6(data: &[u8]) -> anyhow::Result<IpLayer> {
        if data.len() < 40 {
            return Err(anyhow::anyhow!("IPv6 header too short"));
        }

        let version = (data[0] >> 4) & 0x0F;

        if version != 6 {
            return Err(anyhow::anyhow!("Not IPv6"));
        }

        let _traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] & 0xF0) >> 4);
        let _flow_label = BigEndian::read_u32(&[0, data[1] & 0x0F, data[2], data[3]]) & 0x000FFFFF;
        let payload_length = BigEndian::read_u16(&data[4..6]);
        let next_header = data[6];
        let hop_limit = data[7];

        // Ensure we have enough data for IPv6 addresses
        if data.len() < 40 {
            return Err(anyhow::anyhow!("IPv6 header incomplete"));
        }

        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&data[8..24]);
        let src_ip = Ipv6Addr::from(src_bytes);

        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&data[24..40]);
        let dst_ip = Ipv6Addr::from(dst_bytes);

        // Note: IPv6 extension headers are not parsed here for simplicity
        // The next_header field indicates the first extension header or upper layer protocol

        Ok(IpLayer {
            version,
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            protocol: next_header,
            ttl: hop_limit,
            total_length: payload_length + 40, // IPv6 total length includes header
        })
    }

    fn parse_transport(ip_layer: &IpLayer, data: &[u8]) -> anyhow::Result<Layer> {
        let ip_header_len = match ip_layer.version {
            4 => ((data[0] & 0x0F) * 4) as usize,
            6 => 40, // IPv6 fixed header length
            _ => return Err(anyhow::anyhow!("Unsupported IP version")),
        };

        // Validate header length
        let min_header_len = if ip_layer.version == 4 { 20 } else { 40 };
        if ip_header_len < min_header_len {
            return Err(anyhow::anyhow!("Invalid IP header length"));
        }

        if data.len() < ip_header_len {
            return Err(anyhow::anyhow!("Packet too short for transport header"));
        }

        match ip_layer.protocol {
            6 => {
                // TCP
                if data.len() < ip_header_len + 20 {
                    return Err(anyhow::anyhow!("TCP header too short"));
                }
                let tcp_data = &data[ip_header_len..];
                Ok(Layer::Tcp(Self::parse_tcp(tcp_data)?))
            }
            17 => {
                // UDP
                if data.len() < ip_header_len + 8 {
                    return Err(anyhow::anyhow!("UDP header too short"));
                }
                let udp_data = &data[ip_header_len..];
                Ok(Layer::Udp(Self::parse_udp(udp_data)?))
            }
            1 => {
                // ICMP for IPv4, ICMPv6 for IPv6
                if data.len() < ip_header_len + 4 {
                    return Err(anyhow::anyhow!("ICMP header too short"));
                }
                let icmp_data = &data[ip_header_len..];
                Ok(Layer::Icmp(Self::parse_icmp(icmp_data)?))
            }
            58 => {
                // ICMPv6
                if ip_layer.version == 6 {
                    if data.len() < ip_header_len + 4 {
                        return Err(anyhow::anyhow!("ICMPv6 header too short"));
                    }
                    let icmp_data = &data[ip_header_len..];
                    Ok(Layer::Icmp(Self::parse_icmp(icmp_data)?))
                } else {
                    Err(anyhow::anyhow!("ICMPv6 protocol in IPv4 packet"))
                }
            }
            _ => Err(anyhow::anyhow!("Unsupported transport protocol")),
        }
    }

    fn parse_application(transport: &Layer, data: &[u8]) -> anyhow::Result<Layer> {
        if data.is_empty() {
            return Err(anyhow::anyhow!("No application data"));
        }

        match transport {
            Layer::Tcp(tcp) => {
                // Calculate TCP header length (minimum 20 bytes, can be longer with options)
                let tcp_header_len = (tcp.data_offset * 4) as usize;
                // Validate data_offset was set correctly (should be >= 5)
                if tcp.data_offset < 5 || tcp_header_len < 20 || tcp_header_len > 60 {
                    return Err(anyhow::anyhow!("Invalid TCP header length"));
                }
                if data.len() < tcp_header_len {
                    return Err(anyhow::anyhow!("Data too short for TCP header"));
                }
                let app_data = &data[tcp_header_len..];
                
                // Empty payload is valid for some packets (ACKs, etc.)
                if app_data.is_empty() {
                    return Err(anyhow::anyhow!("No TCP payload data"));
                }
                
                // Try to parse HTTP
                if tcp.dst_port == 80 || tcp.src_port == 80 ||
                   tcp.dst_port == 8080 || tcp.src_port == 8080 {
                    if let Ok(http) = Self::parse_http(app_data) {
                        return Ok(Layer::Http(http));
                    }
                }

                // Try to parse SSL/TLS
                if tcp.dst_port == 443 || tcp.src_port == 443 {
                    if let Ok(ssl) = Self::parse_ssl(app_data) {
                        return Ok(Layer::Ssl(ssl));
                    }
                }
            }
            Layer::Udp(udp) => {
                // For UDP, data passed here is after IP header, so it includes UDP header
                // UDP header is 8 bytes, payload starts after that
                if data.len() < 8 {
                    return Err(anyhow::anyhow!("Data too short for UDP header"));
                }
                let app_data = &data[8..];
                
                if app_data.is_empty() {
                    return Err(anyhow::anyhow!("No UDP payload data"));
                }
                
                // Try to parse DNS
                if udp.dst_port == 53 || udp.src_port == 53 {
                    if let Ok(dns) = Self::parse_dns(app_data) {
                        return Ok(Layer::Dns(dns));
                    }
                }
            }
            _ => {}
        }

        Err(anyhow::anyhow!("Unknown application protocol"))
    }

    fn parse_tcp(data: &[u8]) -> anyhow::Result<TcpLayer> {
        if data.len() < 20 {
            return Err(anyhow::anyhow!("TCP header too short"));
        }

        let src_port = BigEndian::read_u16(&data[0..2]);
        let dst_port = BigEndian::read_u16(&data[2..4]);
        let seq = BigEndian::read_u32(&data[4..8]);
        let ack = BigEndian::read_u32(&data[8..12]);
        let data_offset_raw = (data[12] >> 4) & 0x0F;
        // Data offset must be at least 5 (20 bytes minimum header)
        if data_offset_raw < 5 {
            return Err(anyhow::anyhow!("Invalid TCP data offset"));
        }
        let data_offset = data_offset_raw as u8;
        let flags_byte = data[13];
        let window = BigEndian::read_u16(&data[14..16]);

        Ok(TcpLayer {
            src_port,
            dst_port,
            seq,
            ack,
            flags: TcpFlags {
                fin: (flags_byte & 0x01) != 0,
                syn: (flags_byte & 0x02) != 0,
                rst: (flags_byte & 0x04) != 0,
                psh: (flags_byte & 0x08) != 0,
                ack: (flags_byte & 0x10) != 0,
                urg: (flags_byte & 0x20) != 0,
            },
            window,
            data_offset,
        })
    }

    fn parse_udp(data: &[u8]) -> anyhow::Result<UdpLayer> {
        if data.len() < 8 {
            return Err(anyhow::anyhow!("UDP header too short"));
        }

        Ok(UdpLayer {
            src_port: BigEndian::read_u16(&data[0..2]),
            dst_port: BigEndian::read_u16(&data[2..4]),
            length: BigEndian::read_u16(&data[4..6]),
            checksum: BigEndian::read_u16(&data[6..8]),
        })
    }

    fn parse_icmp(data: &[u8]) -> anyhow::Result<IcmpLayer> {
        if data.len() < 4 {
            return Err(anyhow::anyhow!("ICMP header too short"));
        }

        Ok(IcmpLayer {
            icmp_type: data[0],
            icmp_code: data[1],
            checksum: BigEndian::read_u16(&data[2..4]),
        })
    }

    fn parse_arp(data: &[u8]) -> anyhow::Result<ArpLayer> {
        // ARP header is 28 bytes (after Ethernet header)
        // Total structure: 14 bytes Ethernet + 28 bytes ARP = 42 bytes
        if data.len() < 28 {
            return Err(anyhow::anyhow!("ARP header too short"));
        }

        let operation = BigEndian::read_u16(&data[6..8]);
        let src_mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            data[8], data[9], data[10], data[11], data[12], data[13]
        );
        let src_ip = Ipv4Addr::new(data[14], data[15], data[16], data[17]);
        let dst_mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            data[18], data[19], data[20], data[21], data[22], data[23]
        );
        let dst_ip = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

        Ok(ArpLayer {
            operation,
            src_mac,
            src_ip: IpAddr::V4(src_ip),
            dst_mac,
            dst_ip: IpAddr::V4(dst_ip),
        })
    }

    fn parse_http(data: &[u8]) -> anyhow::Result<HttpLayer> {
        use httparse::{Request, Response, Status};

        let mut headers_req = [httparse::EMPTY_HEADER; 64];
        let mut headers_resp = [httparse::EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers_req);
        let mut resp = Response::new(&mut headers_resp);

        // Try parsing as HTTP request first
        if let Ok(Status::Complete(_)) = req.parse(data) {
            let mut http_headers = Vec::new();
            let mut host = None;
            let mut user_agent = None;

            for header in req.headers {
                let name = header.name.to_string();
                let value = String::from_utf8_lossy(header.value).to_string();
                http_headers.push((name.clone(), value.clone()));
                
                if name.to_lowercase() == "host" {
                    host = Some(value);
                } else if name.to_lowercase() == "user-agent" {
                    user_agent = Some(value);
                }
            }

            return Ok(HttpLayer {
                is_request: true,
                method: req.method.map(|s| s.to_string()),
                path: req.path.map(|s| s.to_string()),
                version: req.version.map(|v| format!("HTTP/1.{}", v)),
                status_code: None,
                status_message: None,
                headers: http_headers,
                host,
                user_agent,
            });
        }

        // Try parsing as HTTP response
        if let Ok(Status::Complete(_)) = resp.parse(data) {
            let mut http_headers = Vec::new();
            for header in resp.headers {
                let name = header.name.to_string();
                let value = String::from_utf8_lossy(header.value).to_string();
                http_headers.push((name, value));
            }

            return Ok(HttpLayer {
                is_request: false,
                method: None,
                path: None,
                version: resp.version.map(|v| format!("HTTP/1.{}", v)),
                status_code: resp.code,
                status_message: None,
                headers: http_headers,
                host: None,
                user_agent: None,
            });
        }

        Err(anyhow::anyhow!("Not a valid HTTP packet"))
    }

    fn parse_dns(data: &[u8]) -> anyhow::Result<DnsLayer> {
        use dns_parser::{Packet, RData};

        let packet = Packet::parse(data)?;
        
        let mut questions = Vec::new();
        for q in packet.questions {
            questions.push(DnsQuestion {
                name: q.qname.to_string(),
                qtype: q.qtype as u16,
                qclass: q.qclass as u16,
            });
        }

        let mut answers = Vec::new();
        for answer in packet.answers {
            let mut answer_data = Vec::new();
            let rtype = match answer.data {
                RData::A(addr) => {
                    answer_data = addr.0.octets().to_vec();
                    1 // A record
                }
                RData::AAAA(addr) => {
                    answer_data = addr.0.octets().to_vec();
                    28 // AAAA record
                }
                RData::CNAME(_) => 5,
                RData::MX(_) => 15,
                RData::NS(_) => 2,
                RData::PTR(_) => 12,
                RData::SOA(_) => 6,
                RData::TXT(_) => 16,
                _ => 0,
            };

            answers.push(DnsAnswer {
                name: answer.name.to_string(),
                rtype,
                rclass: answer.cls as u16,
                ttl: answer.ttl,
                data: answer_data,
            });
        }

        Ok(DnsLayer {
            is_response: !packet.header.query,
            transaction_id: packet.header.id,
            questions,
            answers,
        })
    }

    fn parse_ssl(data: &[u8]) -> anyhow::Result<SslLayer> {
        if data.len() < 5 {
            return Err(anyhow::anyhow!("SSL/TLS record too short"));
        }

        let content_type = data[0];
        let version_major = data[1];
        let version_minor = data[2];
        let length = BigEndian::read_u16(&data[3..5]);

        let version = match (version_major, version_minor) {
            (3, 0) => "SSL 3.0".to_string(),
            (3, 1) => "TLS 1.0".to_string(),
            (3, 2) => "TLS 1.1".to_string(),
            (3, 3) => "TLS 1.2".to_string(),
            (3, 4) => "TLS 1.3".to_string(),
            _ => format!("Unknown ({}.{})", version_major, version_minor),
        };

        // For handshake messages, the first byte after header is handshake type
        let handshake_type = if content_type == 22 && data.len() >= 6 { // Handshake
            Some(data[5])
        } else {
            None
        };

        Ok(SslLayer {
            content_type,
            version,
            length,
            handshake_type,
        })
    }
}
