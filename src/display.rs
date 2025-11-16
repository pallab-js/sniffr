use crate::packet::*;
use colored::*;
use chrono::Local;

pub struct DisplayFormatter {
    format: String,
    verbose: bool,
}

impl DisplayFormatter {
    pub fn new(format: String, verbose: bool) -> Self {
        Self { format, verbose }
    }

    pub fn display(&self, packet: &Packet, number: usize) -> anyhow::Result<()> {
        match self.format.as_str() {
            "json" => self.display_json(packet, number),
            "csv" => self.display_csv(packet, number),
            "hex" => {
                self.display_hex(packet, number);
                Ok(())
            }
            "detailed" => {
                self.display_detailed(packet, number);
                Ok(())
            }
            _ => {
                self.display_text(packet, number);
                Ok(())
            }
        }
    }

    fn display_text(&self, packet: &Packet, number: usize) {
        let timestamp = packet.timestamp.with_timezone(&Local)
            .format("%H:%M:%S%.3f");
        
        print!("{} ", number.to_string().bright_blue().bold());
        print!("{} ", timestamp.to_string().bright_black());
        
        if let Some(ip) = packet.get_ip_layer() {
            if let Some(http) = packet.get_http_layer() {
                if let Some(tcp) = packet.get_tcp_layer() {
                    if http.is_request {
                        if let (Some(method), Some(path)) = (&http.method, &http.path) {
                            print!(
                                "{} {} {}:{} → {}:{} {} {} ",
                                "HTTP".bright_cyan().bold(),
                                method.bright_white(),
                                ip.src_ip.to_string().cyan(),
                                tcp.src_port.to_string().yellow(),
                                ip.dst_ip.to_string().cyan(),
                                tcp.dst_port.to_string().yellow(),
                                path.bright_magenta(),
                                http.version.as_deref().unwrap_or("HTTP/1.1").bright_black()
                            );
                        }
                    } else if let Some(status) = http.status_code {
                        print!(
                            "{} {} {} {}:{} → {}:{} ",
                            "HTTP".bright_cyan().bold(),
                            status.to_string().bright_yellow(),
                            http.version.as_deref().unwrap_or("HTTP/1.1").bright_black(),
                            ip.src_ip.to_string().cyan(),
                            tcp.src_port.to_string().yellow(),
                            ip.dst_ip.to_string().cyan(),
                            tcp.dst_port.to_string().yellow(),
                        );
                    }
                }
             } else if let Some(ssl) = packet.get_ssl_layer() {
                 if let Some(tcp) = packet.get_tcp_layer() {
                     print!(
                         "{} {} {}:{} → {}:{} ",
                         "SSL".bright_green().bold(),
                         Self::ssl_content_type_name(ssl.content_type).bright_white(),
                         ip.src_ip.to_string().cyan(),
                         tcp.src_port.to_string().yellow(),
                         ip.dst_ip.to_string().cyan(),
                         tcp.dst_port.to_string().yellow(),
                     );
                 }
             } else if let Some(dns) = packet.get_dns_layer() {
                 if let Some(udp) = packet.get_udp_layer() {
                     let dns_type = if dns.is_response { "Response" } else { "Query" };
                     let query_name = dns.questions.first()
                         .map(|q| q.name.as_str())
                         .unwrap_or("unknown");
                     print!(
                         "{} {} {}:{} → {}:{} {} ",
                         "DNS".bright_blue().bold(),
                         dns_type.bright_white(),
                         ip.src_ip.to_string().cyan(),
                         udp.src_port.to_string().yellow(),
                         ip.dst_ip.to_string().cyan(),
                         udp.dst_port.to_string().yellow(),
                         query_name.bright_magenta()
                     );
                 }
            } else if let Some(tcp) = packet.get_tcp_layer() {
                print!(
                    "{} {}:{} → {}:{} ",
                    "TCP".bright_green().bold(),
                    ip.src_ip.to_string().cyan(),
                    tcp.src_port.to_string().yellow(),
                    ip.dst_ip.to_string().cyan(),
                    tcp.dst_port.to_string().yellow(),
                );
                if !tcp.flags.to_string().is_empty() {
                    print!("[{}] ", tcp.flags.to_string().bright_magenta());
                }
                print!("Len={} ", packet.length.to_string().bright_white());
            } else if let Some(udp) = packet.get_udp_layer() {
                print!(
                    "{} {}:{} → {}:{} ",
                    "UDP".bright_yellow().bold(),
                    ip.src_ip.to_string().cyan(),
                    udp.src_port.to_string().yellow(),
                    ip.dst_ip.to_string().cyan(),
                    udp.dst_port.to_string().yellow(),
                );
                print!("Len={} ", packet.length.to_string().bright_white());
            } else if let Some(icmp) = packet.layers.iter().find_map(|l| {
                if let Layer::Icmp(icmp) = l { Some(icmp) } else { None }
            }) {
                print!(
                    "{} {} → {} ",
                    "ICMP".bright_red().bold(),
                    ip.src_ip.to_string().cyan(),
                    ip.dst_ip.to_string().cyan(),
                );
                print!("Type={} Code={} ", 
                    icmp.icmp_type.to_string().yellow(),
                    icmp.icmp_code.to_string().yellow());
            } else {
                print!(
                    "IP {} → {} ",
                    ip.src_ip.to_string().cyan(),
                    ip.dst_ip.to_string().cyan(),
                );
            }
        } else if let Some(arp) = packet.get_arp_layer() {
            let op = if arp.operation == 1 { "Request" } else { "Reply" };
            print!(
                "ARP {} {} → {} ",
                op.bright_white(),
                arp.src_ip.to_string().cyan(),
                arp.dst_ip.to_string().cyan(),
            );
            print!("{} → {} ", arp.src_mac.bright_white(), arp.dst_mac.bright_white());
        } else if let Some(eth) = packet.layers.iter().find_map(|l| {
            if let Layer::Ethernet(eth) = l { Some(eth) } else { None }
        }) {
            print!(
                "Ethernet {} → {} ",
                eth.src_mac.bright_white(),
                eth.dst_mac.bright_white(),
            );
        }
        
        println!();
        
        if self.verbose {
            self.display_verbose(packet);
        }
    }

    fn display_detailed(&self, packet: &Packet, number: usize) {
        let timestamp = packet.timestamp.with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S%.3f");
        
        println!("{}", "=".repeat(80).bright_black());
        println!("{} Packet #{}", "Packet".green().bold(), number.to_string().bright_blue());
        println!("{}", "=".repeat(80).bright_black());
        println!("Timestamp: {}", timestamp.to_string().cyan());
        println!("Length: {} bytes", packet.length.to_string().yellow());
        println!();
        
        for layer in &packet.layers {
            match layer {
                Layer::Ethernet(eth) => {
                    println!("{}", "Ethernet Layer".bright_white().bold());
                    println!("  Source MAC:      {}", eth.src_mac.cyan());
                    println!("  Destination MAC: {}", eth.dst_mac.cyan());
                    println!("  EtherType:       0x{:04x}", eth.ethertype);
                }
                Layer::Ip(ip) => {
                    println!("{}", "IP Layer".bright_white().bold());
                    println!("  Version:         IPv{}", ip.version);
                    println!("  Source IP:       {}", ip.src_ip.to_string().cyan());
                    println!("  Destination IP:  {}", ip.dst_ip.to_string().cyan());
                    println!("  Protocol:        {} ({})", 
                        Self::protocol_name(ip.protocol),
                        ip.protocol);
                    println!("  TTL:             {}", ip.ttl);
                    println!("  Total Length:    {} bytes", ip.total_length);
                }
                Layer::Tcp(tcp) => {
                    println!("{}", "TCP Layer".bright_white().bold());
                    println!("  Source Port:     {}", tcp.src_port.to_string().yellow());
                    println!("  Destination Port: {}", tcp.dst_port.to_string().yellow());
                    println!("  Sequence:        {}", tcp.seq);
                    println!("  Acknowledgment:  {}", tcp.ack);
                    println!("  Flags:           {}", tcp.flags.to_string().bright_magenta());
                    println!("  Window:          {}", tcp.window);
                    println!("  Data Offset:     {} bytes", tcp.data_offset * 4);
                }
                Layer::Udp(udp) => {
                    println!("{}", "UDP Layer".bright_white().bold());
                    println!("  Source Port:     {}", udp.src_port.to_string().yellow());
                    println!("  Destination Port: {}", udp.dst_port.to_string().yellow());
                    println!("  Length:          {} bytes", udp.length);
                    println!("  Checksum:        0x{:04x}", udp.checksum);
                }
                Layer::Icmp(icmp) => {
                    println!("{}", "ICMP Layer".bright_white().bold());
                    println!("  Type:            {}", icmp.icmp_type);
                    println!("  Code:            {}", icmp.icmp_code);
                    println!("  Checksum:        0x{:04x}", icmp.checksum);
                }
                Layer::Http(http) => {
                    println!("{}", "HTTP Layer".bright_white().bold());
                    if http.is_request {
                        if let Some(method) = &http.method {
                            println!("  Method:          {}", method.bright_green());
                        }
                        if let Some(path) = &http.path {
                            println!("  Path:            {}", path.bright_cyan());
                        }
                        if let Some(host) = &http.host {
                            println!("  Host:            {}", host.bright_white());
                        }
                    } else {
                        if let Some(code) = http.status_code {
                            println!("  Status Code:     {}", code.to_string().bright_yellow());
                        }
                    }
                    if let Some(version) = &http.version {
                        println!("  Version:         {}", version);
                    }
                }
                Layer::Dns(dns) => {
                    println!("{}", "DNS Layer".bright_white().bold());
                    println!("  Type:            {}", if dns.is_response { "Response" } else { "Query" });
                    println!("  Transaction ID:  0x{:04x}", dns.transaction_id);
                    for q in &dns.questions {
                        println!("  Question:        {} (Type: {})", q.name.bright_cyan(), q.qtype);
                    }
                    for a in &dns.answers {
                        println!("  Answer:          {} (TTL: {})", a.name.bright_cyan(), a.ttl);
                    }
                }
                 Layer::Arp(arp) => {
                     println!("{}", "ARP Layer".bright_white().bold());
                     println!("  Operation:       {}", if arp.operation == 1 { "Request" } else { "Reply" });
                     println!("  Source MAC:      {}", arp.src_mac.cyan());
                     println!("  Source IP:       {}", arp.src_ip.to_string().cyan());
                     println!("  Destination MAC: {}", arp.dst_mac.cyan());
                     println!("  Destination IP:  {}", arp.dst_ip.to_string().cyan());
                 }
                 Layer::Ssl(ssl) => {
                     println!("{}", "SSL/TLS Layer".bright_white().bold());
                     println!("  Content Type:    {}", Self::ssl_content_type_name(ssl.content_type));
                     println!("  Version:         {}", ssl.version);
                     println!("  Length:          {} bytes", ssl.length);
                     if let Some(ht) = ssl.handshake_type {
                         println!("  Handshake Type:  {}", Self::ssl_handshake_type_name(ht));
                     }
                 }
                Layer::Unknown(name) => {
                    println!("{}", format!("Unknown Layer: {}", name).bright_black());
                }
            }
            println!();
        }
    }

    fn display_verbose(&self, packet: &Packet) {
        for layer in &packet.layers {
            match layer {
                Layer::Ethernet(eth) => {
                    println!("    {} → {} (EtherType: 0x{:04x})",
                        eth.src_mac.bright_black(),
                        eth.dst_mac.bright_black(),
                        eth.ethertype);
                }
                Layer::Ip(ip) => {
                    println!("    {} → {} Protocol: {}",
                        ip.src_ip.to_string().bright_black(),
                        ip.dst_ip.to_string().bright_black(),
                        Self::protocol_name(ip.protocol).bright_black());
                }
                Layer::Tcp(tcp) => {
                    println!("    Port {} → {} Flags: {}",
                        tcp.src_port.to_string().bright_black(),
                        tcp.dst_port.to_string().bright_black(),
                        tcp.flags.to_string().bright_black());
                }
                Layer::Udp(udp) => {
                    println!("    Port {} → {}",
                        udp.src_port.to_string().bright_black(),
                        udp.dst_port.to_string().bright_black());
                }
                Layer::Http(http) => {
                    if let (Some(method), Some(path)) = (&http.method, &http.path) {
                        println!("    {} {}", method.bright_black(), path.bright_black());
                    }
                }
                Layer::Dns(dns) => {
                    if let Some(q) = dns.questions.first() {
                        println!("    {} {}", 
                            if dns.is_response { "Response" } else { "Query" }.bright_black(),
                            q.name.bright_black());
                    }
                }
                Layer::Arp(arp) => {
                    println!("    {} {} → {}",
                        if arp.operation == 1 { "Request" } else { "Reply" }.bright_black(),
                        arp.src_ip.to_string().bright_black(),
                        arp.dst_ip.to_string().bright_black());
                }
                _ => {}
            }
        }
    }

    fn display_json(&self, packet: &Packet, number: usize) -> anyhow::Result<()> {
        let mut json = serde_json::json!({
            "number": number,
            "timestamp": packet.timestamp.to_rfc3339(),
            "length": packet.length,
            "layers": []
        });

        let layers_array = json["layers"].as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("Failed to access layers array"))?;

        for layer in &packet.layers {
            match layer {
                Layer::Ethernet(eth) => {
                    layers_array.push(serde_json::json!({
                        "type": "ethernet",
                        "src_mac": eth.src_mac,
                        "dst_mac": eth.dst_mac,
                        "ethertype": format!("0x{:04x}", eth.ethertype)
                    }));
                }
                Layer::Ip(ip) => {
                    layers_array.push(serde_json::json!({
                        "type": "ip",
                        "version": ip.version,
                        "src_ip": ip.src_ip.to_string(),
                        "dst_ip": ip.dst_ip.to_string(),
                        "protocol": ip.protocol,
                        "protocol_name": Self::protocol_name(ip.protocol),
                        "ttl": ip.ttl,
                        "total_length": ip.total_length
                    }));
                }
                Layer::Tcp(tcp) => {
                    layers_array.push(serde_json::json!({
                        "type": "tcp",
                        "src_port": tcp.src_port,
                        "dst_port": tcp.dst_port,
                        "seq": tcp.seq,
                        "ack": tcp.ack,
                        "flags": {
                            "fin": tcp.flags.fin,
                            "syn": tcp.flags.syn,
                            "rst": tcp.flags.rst,
                            "psh": tcp.flags.psh,
                            "ack": tcp.flags.ack,
                            "urg": tcp.flags.urg
                        },
                        "window": tcp.window,
                        "data_offset": tcp.data_offset
                    }));
                }
                Layer::Udp(udp) => {
                    layers_array.push(serde_json::json!({
                        "type": "udp",
                        "src_port": udp.src_port,
                        "dst_port": udp.dst_port,
                        "length": udp.length,
                        "checksum": format!("0x{:04x}", udp.checksum)
                    }));
                }
                Layer::Icmp(icmp) => {
                    layers_array.push(serde_json::json!({
                        "type": "icmp",
                        "icmp_type": icmp.icmp_type,
                        "icmp_code": icmp.icmp_code,
                        "checksum": format!("0x{:04x}", icmp.checksum)
                    }));
                }
                Layer::Http(http) => {
                    layers_array.push(serde_json::json!({
                        "type": "http",
                        "is_request": http.is_request,
                        "method": http.method,
                        "path": http.path,
                        "version": http.version,
                        "status_code": http.status_code,
                        "status_message": http.status_message,
                        "host": http.host,
                        "user_agent": http.user_agent,
                        "headers": http.headers
                    }));
                }
                Layer::Dns(dns) => {
                    layers_array.push(serde_json::json!({
                        "type": "dns",
                        "is_response": dns.is_response,
                        "transaction_id": dns.transaction_id,
                        "questions": dns.questions.iter().map(|q| serde_json::json!({
                            "name": q.name,
                            "qtype": q.qtype,
                            "qclass": q.qclass
                        })).collect::<Vec<_>>(),
                        "answers": dns.answers.iter().map(|a| serde_json::json!({
                            "name": a.name,
                            "rtype": a.rtype,
                            "rclass": a.rclass,
                            "ttl": a.ttl
                        })).collect::<Vec<_>>()
                    }));
                }
                 Layer::Arp(arp) => {
                     layers_array.push(serde_json::json!({
                         "type": "arp",
                         "operation": arp.operation,
                         "src_mac": arp.src_mac,
                         "src_ip": arp.src_ip.to_string(),
                         "dst_mac": arp.dst_mac,
                         "dst_ip": arp.dst_ip.to_string()
                     }));
                 }
                 Layer::Ssl(ssl) => {
                     layers_array.push(serde_json::json!({
                         "type": "ssl",
                         "content_type": ssl.content_type,
                         "version": ssl.version,
                         "length": ssl.length,
                         "handshake_type": ssl.handshake_type
                     }));
                 }
                Layer::Unknown(name) => {
                    layers_array.push(serde_json::json!({
                        "type": "unknown",
                        "name": name
                    }));
                }
            }
        }

        println!("{}", serde_json::to_string_pretty(&json)?);
        Ok(())
    }

    fn display_csv(&self, packet: &Packet, number: usize) -> anyhow::Result<()> {
        use csv::Writer;
        use std::io::stdout;
        use std::sync::atomic::{AtomicBool, Ordering};

        static HEADER_PRINTED: AtomicBool = AtomicBool::new(false);
        
        let mut wtr = Writer::from_writer(stdout());
        
        // Print header only once
        if !HEADER_PRINTED.swap(true, Ordering::Relaxed) {
            wtr.write_record(&["number", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "length"])?;
        }

        let timestamp = packet.timestamp.to_rfc3339();
        let src_ip = packet.get_ip_layer()
            .map(|ip| ip.src_ip.to_string())
            .unwrap_or_else(|| "".to_string());
        let dst_ip = packet.get_ip_layer()
            .map(|ip| ip.dst_ip.to_string())
            .unwrap_or_else(|| "".to_string());
        let src_port = packet.get_tcp_layer()
            .map(|tcp| tcp.src_port.to_string())
            .or_else(|| packet.get_udp_layer().map(|udp| udp.src_port.to_string()))
            .unwrap_or_else(|| "".to_string());
        let dst_port = packet.get_tcp_layer()
            .map(|tcp| tcp.dst_port.to_string())
            .or_else(|| packet.get_udp_layer().map(|udp| udp.dst_port.to_string()))
            .unwrap_or_else(|| "".to_string());
         let protocol = if packet.get_ssl_layer().is_some() {
             "SSL"
         } else if packet.get_http_layer().is_some() {
             "HTTP"
         } else if packet.get_dns_layer().is_some() {
             "DNS"
         } else if packet.get_tcp_layer().is_some() {
             "TCP"
         } else if packet.get_udp_layer().is_some() {
             "UDP"
         } else if packet.get_arp_layer().is_some() {
             "ARP"
         } else {
             "Other"
         };

        wtr.write_record(&[
            number.to_string(),
            timestamp,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol.to_string(),
            packet.length.to_string(),
        ])?;
        wtr.flush()?;
        Ok(())
    }

    fn display_hex(&self, packet: &Packet, number: usize) {
        println!("Packet #{} - Hex Dump", number);
        println!("Length: {} bytes (captured: {} bytes)", packet.length, packet.captured_length);
        println!("Timestamp: {}", packet.timestamp.to_rfc3339());
        println!();

        // Display hex dump with 16 bytes per line
        for (i, chunk) in packet.raw_data.chunks(16).enumerate() {
            let offset = i * 16;
            print!("{:08x}: ", offset);

            // Hex bytes
            for (j, &byte) in chunk.iter().enumerate() {
                if j == 8 {
                    print!(" ");
                }
                print!("{:02x} ", byte);
            }

            // Padding for incomplete lines
            let padding = 16 - chunk.len();
            for _ in 0..padding {
                print!("   ");
            }
            if chunk.len() <= 8 {
                print!(" ");
            }

            // ASCII representation
            print!(" |");
            for &byte in chunk {
                let c = if byte.is_ascii_graphic() { byte as char } else { '.' };
                print!("{}", c);
            }
            println!("|");
        }
        println!();
    }

    fn protocol_name(protocol: u8) -> &'static str {
        match protocol {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            41 => "IPv6",
            47 => "GRE",
            50 => "ESP",
            51 => "AH",
            _ => "Unknown",
        }
    }

    fn ssl_content_type_name(content_type: u8) -> &'static str {
        match content_type {
            20 => "ChangeCipherSpec",
            21 => "Alert",
            22 => "Handshake",
            23 => "ApplicationData",
            24 => "Heartbeat",
            _ => "Unknown",
        }
    }

    fn ssl_handshake_type_name(handshake_type: u8) -> &'static str {
        match handshake_type {
            0 => "HelloRequest",
            1 => "ClientHello",
            2 => "ServerHello",
            11 => "Certificate",
            12 => "ServerKeyExchange",
            13 => "CertificateRequest",
            14 => "ServerHelloDone",
            15 => "CertificateVerify",
            16 => "ClientKeyExchange",
            20 => "Finished",
            _ => "Unknown",
        }
    }
}
