use clap::{Parser, Subcommand};
use colored::*;
use std::process;

mod capture;
mod packet;
mod parser;
mod display;
mod stats;

use capture::Capture;
use display::DisplayFormatter;
use stats::CaptureStats;

#[derive(Parser)]
#[command(name = "tshark-clone")]
#[command(about = "A modern, user-friendly packet capture and analysis tool", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Capture and analyze packets from a network interface
    Capture {
        /// Network interface to capture from (e.g., eth0, en0, wlan0)
        #[arg(short, long)]
        interface: Option<String>,
        
        /// Number of packets to capture (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        count: usize,
        
        /// Display filter (e.g., "tcp port 80", "ip src 192.168.1.1")
        #[arg(short, long)]
        filter: Option<String>,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
        
        /// Output format: text, json, detailed, csv, or hex
        #[arg(short, long, default_value = "text")]
        format: String,
        
        /// Output file to save packets (pcap format)
        #[arg(short = 'w', long)]
        write: Option<String>,
    },
    /// Read and analyze packets from a pcap file
    Read {
        /// Input pcap file
        #[arg(short, long)]
        file: String,
        
        /// Number of packets to read (0 = all)
        #[arg(short, long, default_value = "0")]
        count: usize,
        
        /// Display filter
        #[arg(short, long)]
        filter: Option<String>,
        
        /// Output format: text, json, detailed, csv, or hex
        #[arg(short, long, default_value = "text")]
        format: String,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Show statistics for captured packets
    Stats {
        /// Network interface (for live capture)
        #[arg(short, long)]
        interface: Option<String>,
        
        /// Input pcap file (for file analysis)
        #[arg(short, long)]
        file: Option<String>,
        
        /// Display filter
        #[arg(short, long)]
        filter: Option<String>,
        
        /// Number of packets to analyze (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        count: usize,
    },
    /// List available network interfaces
    Interfaces,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Capture {
            interface,
            count,
            filter,
            verbose,
            format,
            write,
        } => {
            capture_packets(interface, count, filter, verbose, format, write)
        }
        Commands::Read {
            file,
            count,
            filter,
            format,
            verbose,
        } => {
            read_packets(file, count, filter, format, verbose)
        }
        Commands::Stats {
            interface,
            file,
            filter,
            count,
        } => {
            show_stats(interface, file, filter, count)
        }
        Commands::Interfaces => list_interfaces(),
    };

    if let Err(e) = result {
        eprintln!("{}: {}", "Error".red().bold(), e);
        process::exit(1);
    }
}

fn capture_packets(
    interface: Option<String>,
    count: usize,
    filter: Option<String>,
    verbose: bool,
    format: String,
    write: Option<String>,
) -> anyhow::Result<()> {
    let mut capture = Capture::new(interface.as_deref(), filter.as_deref())?;
    
    if let Some(filename) = &write {
        capture = capture.with_savefile(filename)?;
        println!("{}: Saving packets to {}", "Info".green().bold(), filename.cyan());
    }
    
    let formatter = DisplayFormatter::new(format.clone(), verbose);
    let mut stats = CaptureStats::new();

    if format != "csv" {
        println!("{}", "Starting packet capture...".green().bold());
        if let Some(iface) = &interface {
            println!("Interface: {}", iface.cyan());
        } else {
            println!("Interface: {}", "default".cyan());
        }
        if let Some(f) = &filter {
            println!("Filter: {}", f.cyan());
        }
        if let Some(ref filename) = write {
            println!("Output file: {}", filename.cyan());
        }
        println!("Press Ctrl+C to stop\n");
    }

    capture.start()?;

    loop {
        match capture.next_packet() {
            Ok(Some(packet)) => {
                stats.add_packet(&packet);
                formatter.display(&packet, stats.packet_count)?;

                if count > 0 && stats.packet_count >= count {
                    break;
                }
            }
            Ok(None) => {
                continue;
            }
            Err(e) => {
                eprintln!("{}: {}", "Error reading packet".yellow(), e);
                continue;
            }
        }
    }

    display_summary(&stats);
    Ok(())
}

fn read_packets(
    file: String,
    count: usize,
    filter: Option<String>,
    format: String,
    verbose: bool,
) -> anyhow::Result<()> {
    let mut capture = Capture::from_file(&file, filter.as_deref())?;
    let formatter = DisplayFormatter::new(format.clone(), verbose);
    let mut stats = CaptureStats::new();

    if format != "csv" {
        println!("{}: Reading packets from {}", "Info".green().bold(), file.cyan());
        if let Some(f) = &filter {
            println!("Filter: {}", f.cyan());
        }
        println!();
    }

    capture.start()?;

    loop {
        match capture.next_packet() {
            Ok(Some(packet)) => {
                stats.add_packet(&packet);
                formatter.display(&packet, stats.packet_count)?;

                if count > 0 && stats.packet_count >= count {
                    break;
                }
            }
            Ok(None) => {
                break; // End of file
            }
            Err(e) => {
                eprintln!("{}: {}", "Error reading packet".yellow(), e);
                continue;
            }
        }
    }

    if format != "csv" {
        display_summary(&stats);
    }
    Ok(())
}

fn show_stats(
    interface: Option<String>,
    file: Option<String>,
    filter: Option<String>,
    count: usize,
) -> anyhow::Result<()> {
    // Validate that either file or interface is provided, but not both
    if file.is_some() && interface.is_some() {
        return Err(anyhow::anyhow!("Cannot specify both file and interface. Use either --file or --interface."));
    }
    
    if file.is_none() && interface.is_none() {
        return Err(anyhow::anyhow!("Must specify either --file or --interface for statistics mode."));
    }
    
    let is_file = file.is_some();
    let mut capture = if let Some(ref f) = file {
        Capture::from_file(f, filter.as_deref())?
    } else {
        Capture::new(interface.as_deref(), filter.as_deref())?
    };
    
    let mut stats = CaptureStats::new();

    println!("{}", "Collecting statistics...".green().bold());
    capture.start()?;

    loop {
        match capture.next_packet() {
            Ok(Some(packet)) => {
                stats.add_packet(&packet);
                if count > 0 && stats.packet_count >= count {
                    break;
                }
            }
            Ok(None) => {
                if is_file {
                    break; // End of file
                }
                continue;
            }
            Err(e) => {
                eprintln!("{}: {}", "Error".yellow(), e);
                continue;
            }
        }
    }

    display_stats(&stats);
    Ok(())
}

fn display_summary(stats: &CaptureStats) {
    println!("\n{}", "=".repeat(60).bright_black());
    println!("{}", "Capture Summary".green().bold());
    println!("{}", "=".repeat(60).bright_black());
    println!("Packets captured: {}", stats.packet_count.to_string().cyan());
    println!("Total bytes: {}", format_bytes(stats.total_bytes).cyan());
    
    if let Some(duration) = stats.duration() {
        let millis = duration.num_milliseconds();
        if millis != 0 {
            let secs = millis as f64 / 1000.0;
            println!("Duration: {:.3} seconds", secs.to_string().cyan());
            println!("Packets/sec: {:.2}", stats.packets_per_second().to_string().cyan());
            println!("Bytes/sec: {}", format_bytes(stats.bytes_per_second() as usize).cyan());
        } else {
            println!("Duration: < 1ms");
        }
    }
    
    if !stats.protocol_counts.is_empty() {
        println!("\nProtocol Distribution:");
        let mut protocols: Vec<_> = stats.protocol_counts.iter().collect();
        protocols.sort_by(|a, b| b.1.cmp(a.1));
        for (proto, count) in protocols {
            let pct = if stats.packet_count > 0 {
                (*count as f64 / stats.packet_count as f64 * 100.0) as usize
            } else {
                0
            };
            println!("  {}: {} ({}%)", proto.bright_white(), count.to_string().cyan(), pct.to_string().yellow());
        }
    }
}

fn display_stats(stats: &CaptureStats) {
    display_summary(stats);
    
    let conversations = stats.top_conversations(10);
    if !conversations.is_empty() {
        println!("\n{}", "Top Conversations:".green().bold());
        for (idx, ((src, dst), count)) in conversations.iter().enumerate() {
            println!("  {}. {} ? {} ({} packets)", 
                idx + 1,
                src.to_string().cyan(),
                dst.to_string().cyan(),
                count.to_string().yellow()
            );
        }
    }
    
    let talkers = stats.top_talkers_list(10);
    if !talkers.is_empty() {
        println!("\n{}", "Top Talkers:".green().bold());
        for (idx, (ip, count)) in talkers.iter().enumerate() {
            println!("  {}. {} ({} packets)", 
                idx + 1,
                ip.to_string().cyan(),
                count.to_string().yellow()
            );
        }
    }
    
    let ports = stats.top_ports(10);
    if !ports.is_empty() {
        println!("\n{}", "Top Ports:".green().bold());
        for (idx, (port, count)) in ports.iter().enumerate() {
            println!("  {}. Port {} ({} packets)", 
                idx + 1,
                port.to_string().cyan(),
                count.to_string().yellow()
            );
        }
    }
}

fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn list_interfaces() -> anyhow::Result<()> {
    let interfaces = Capture::list_interfaces()?;
    
    println!("{}", "Available Network Interfaces:".green().bold());
    println!();
    
    for (idx, iface) in interfaces.iter().enumerate() {
        println!(
            "  {}. {} ({})",
            (idx + 1).to_string().cyan(),
            iface.name.bright_white(),
            iface.description.as_deref().unwrap_or("No description").yellow()
        );
    }
    
    Ok(())
}
