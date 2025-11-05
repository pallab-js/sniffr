use crate::packet::*;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Default, Clone)]
pub struct CaptureStats {
    pub packet_count: usize,
    pub total_bytes: usize,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub protocol_counts: HashMap<String, usize>,
    pub conversations: HashMap<(IpAddr, IpAddr), usize>,
    pub port_counts: HashMap<u16, usize>,
    pub top_talkers: HashMap<IpAddr, usize>,
}

impl CaptureStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_packet(&mut self, packet: &Packet) {
        self.packet_count += 1;
        self.total_bytes += packet.length;

        if self.start_time.is_none() {
            self.start_time = Some(packet.timestamp);
        }
        self.end_time = Some(packet.timestamp);

        // Count protocols - only count transport/application layers to avoid double counting
        let protocol_name = if packet.get_http_layer().is_some() {
            "HTTP"
        } else if packet.get_dns_layer().is_some() {
            "DNS"
        } else if packet.get_tcp_layer().is_some() {
            "TCP"
        } else if packet.get_udp_layer().is_some() {
            "UDP"
        } else if packet.get_icmp_layer().is_some() {
            "ICMP"
        } else if packet.get_arp_layer().is_some() {
            "ARP"
        } else if let Some(ip) = packet.get_ip_layer() {
            match ip.protocol {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                _ => "Other IP",
            }
        } else {
            "Ethernet"
        };
        *self.protocol_counts.entry(protocol_name.to_string()).or_insert(0) += 1;

        // Track conversations
        if let Some(ip) = packet.get_ip_layer() {
            let conversation = if ip.src_ip < ip.dst_ip {
                (ip.src_ip, ip.dst_ip)
            } else {
                (ip.dst_ip, ip.src_ip)
            };
            *self.conversations.entry(conversation).or_insert(0) += 1;

            // Track top talkers
            *self.top_talkers.entry(ip.src_ip).or_insert(0) += 1;
            *self.top_talkers.entry(ip.dst_ip).or_insert(0) += 1;

            // Track ports
            if let Some(tcp) = packet.get_tcp_layer() {
                *self.port_counts.entry(tcp.src_port).or_insert(0) += 1;
                *self.port_counts.entry(tcp.dst_port).or_insert(0) += 1;
            } else if let Some(udp) = packet.get_udp_layer() {
                *self.port_counts.entry(udp.src_port).or_insert(0) += 1;
                *self.port_counts.entry(udp.dst_port).or_insert(0) += 1;
            }
        }
    }

    pub fn duration(&self) -> Option<chrono::Duration> {
        if let (Some(start), Some(end)) = (self.start_time, self.end_time) {
            Some(end - start)
        } else {
            None
        }
    }

    pub fn packets_per_second(&self) -> f64 {
        if let Some(duration) = self.duration() {
            // Handle potential overflow in num_milliseconds
            let millis = duration.num_milliseconds();
            if millis == 0 {
                return 0.0;
            }
            let secs = millis as f64 / 1000.0;
            if secs > 0.0 {
                self.packet_count as f64 / secs
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    pub fn bytes_per_second(&self) -> f64 {
        if let Some(duration) = self.duration() {
            // Handle potential overflow in num_milliseconds
            let millis = duration.num_milliseconds();
            if millis == 0 {
                return 0.0;
            }
            let secs = millis as f64 / 1000.0;
            if secs > 0.0 {
                self.total_bytes as f64 / secs
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    pub fn top_conversations(&self, n: usize) -> Vec<((IpAddr, IpAddr), usize)> {
        let mut convs: Vec<_> = self.conversations.iter().collect();
        convs.sort_by(|a, b| b.1.cmp(a.1));
        convs.into_iter().take(n).map(|(k, v)| (*k, *v)).collect()
    }

    pub fn top_talkers_list(&self, n: usize) -> Vec<(IpAddr, usize)> {
        let mut talkers: Vec<_> = self.top_talkers.iter().collect();
        talkers.sort_by(|a, b| b.1.cmp(a.1));
        talkers.into_iter().take(n).map(|(k, v)| (*k, *v)).collect()
    }

    pub fn top_ports(&self, n: usize) -> Vec<(u16, usize)> {
        let mut ports: Vec<_> = self.port_counts.iter().collect();
        ports.sort_by(|a, b| b.1.cmp(a.1));
        ports.into_iter().take(n).map(|(k, v)| (*k, *v)).collect()
    }
}
