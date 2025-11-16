use crate::parser::PacketParser;
use crate::packet::Packet;
use pcap::{Device, Capture as PcapCapture, Active, Offline};

pub enum CaptureType {
    Live(PcapCapture<Active>),
    File(PcapCapture<Offline>),
}

pub struct Capture {
    cap: Option<CaptureType>,
    filter: Option<String>,
    savefile: Option<pcap::Savefile>,
}

pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
}

impl Capture {
    pub fn new(interface: Option<&str>, filter: Option<&str>) -> anyhow::Result<Self> {
        let device = if let Some(iface) = interface {
            Device::list()?
                .into_iter()
                .find(|d| d.name == iface)
                .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", iface))?
        } else {
            Device::list()?
                .into_iter()
                .find(|d| !d.addresses.is_empty())
                .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?
        };

        let mut cap = PcapCapture::from_device(device)?
            .promisc(true)
            .timeout(100)
            .open()?;

        if let Some(f) = filter {
            cap.filter(f, true)?;
        }

        Ok(Self {
            cap: Some(CaptureType::Live(cap)),
            filter: filter.map(|s| s.to_string()),
            savefile: None,
        })
    }

    pub fn from_file(file: &str, filter: Option<&str>) -> anyhow::Result<Self> {
        // Check if file exists and is readable
        if !std::path::Path::new(file).exists() {
            return Err(anyhow::anyhow!("File '{}' does not exist", file));
        }
        
        let mut cap = PcapCapture::from_file(file)
            .map_err(|e| anyhow::anyhow!("Failed to open file '{}': {}", file, e))?;

        if let Some(f) = filter {
            cap.filter(f, true)
                .map_err(|e| anyhow::anyhow!("Invalid filter '{}': {}", f, e))?;
        }

        Ok(Self {
            cap: Some(CaptureType::File(cap)),
            filter: filter.map(|s| s.to_string()),
            savefile: None,
        })
    }

    pub fn with_savefile(mut self, filename: &str) -> anyhow::Result<Self> {
        match self.cap {
            Some(CaptureType::Live(ref mut cap)) => {
                self.savefile = Some(cap.savefile(filename)?);
            }
            Some(CaptureType::File(_)) => {
                return Err(anyhow::anyhow!("Cannot write to file when reading from file. Use separate commands."));
            }
            None => {
                return Err(anyhow::anyhow!("Capture not initialized"));
            }
        }
        Ok(self)
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        // Capture is already started when opened
        Ok(())
    }

    pub fn next_packet(&mut self) -> anyhow::Result<Option<Packet>> {
        if let Some(ref mut cap) = self.cap {
            let pcap_packet = match cap {
                CaptureType::Live(c) => match c.next_packet() {
                    Ok(p) => p,
                    Err(pcap::Error::TimeoutExpired) => return Ok(None),
                    Err(e) => return Err(anyhow::anyhow!("Error capturing packet: {}", e)),
                },
                CaptureType::File(c) => match c.next_packet() {
                    Ok(p) => p,
                    Err(pcap::Error::NoMorePackets) => return Ok(None),
                    Err(e) => return Err(anyhow::anyhow!("Error reading packet: {}", e)),
                },
            };

            // Convert pcap timestamp to UTC
            // Handle potential overflow in microseconds conversion
            // pcap uses microseconds (0-999999), chrono uses nanoseconds (0-999999999)
            let micros = pcap_packet.header.ts.tv_usec as u32;
            let nanos = (micros.saturating_mul(1000)).min(999_999_999);
            let timestamp = chrono::DateTime::from_timestamp(
                pcap_packet.header.ts.tv_sec,
                nanos,
            ).unwrap_or_else(chrono::Utc::now);
            
            let mut parsed = PacketParser::parse(pcap_packet.data)?;
            parsed.timestamp = timestamp;
            
            // Save to file if configured
            if let Some(ref mut savefile) = self.savefile {
                // Attempt to write packet to file
                savefile.write(&pcap_packet);

                // Check for potential write errors by attempting a flush
                // Note: This is a workaround since pcap::Savefile::write doesn't return errors
                // In a real implementation, you might want to use a custom writer that tracks errors
                // For now, we assume writes succeed and handle failures at higher levels if needed
            }
            
            // Apply filter if specified (for application-level filtering)
            if let Some(ref filter) = self.filter {
                if !parsed.matches_filter(filter) {
                    return Ok(None);
                }
            }
            
            Ok(Some(parsed))
        } else {
            Err(anyhow::anyhow!("Capture not initialized"))
        }
    }

    pub fn list_interfaces() -> anyhow::Result<Vec<InterfaceInfo>> {
        let devices = Device::list()?;
        Ok(devices
            .into_iter()
            .map(|d| InterfaceInfo {
                name: d.name.clone(),
                description: d.desc.clone(),
            })
            .collect())
    }
}
