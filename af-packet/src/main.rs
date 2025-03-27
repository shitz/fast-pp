use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use nix::libc::sockaddr_ll;
use nix::sys::socket::*;

struct AfPacketSocket {
    fd: OwnedFd,
}

impl AfPacketSocket {
    fn new(interface_name: &str) -> nix::Result<Self> {
        // Get interface index
        let interface_index = nix::net::if_::if_nametoindex(interface_name)?;

        // Create raw socket using nix
        let fd = socket(
            AddressFamily::Packet,
            SockType::Datagram,
            SockFlag::SOCK_NONBLOCK,
            SockProtocol::EthAll,
        )?;

        // Bind to specific interface
        let addr = &sockaddr_ll {
            sll_family: nix::libc::AF_PACKET as u16,
            sll_protocol: 0,
            sll_ifindex: interface_index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        } as *const sockaddr_ll;
        let sockaddr = unsafe { std::mem::transmute::<*const sockaddr_ll, *const sockaddr>(addr) };
        let sockaddr = unsafe { LinkAddr::from_raw(sockaddr, None).unwrap() };

        bind(fd.as_raw_fd(), &sockaddr)?;

        Ok(Self { fd })
    }

    /// Read a packet from the socket
    fn read_packet(&self, buffer: &mut [u8]) -> nix::Result<usize> {
        // Use std::os::fd to read from raw file descriptor
        nix::unistd::read(self.fd.as_raw_fd(), buffer)
    }

    /// Write a packet to the socket
    #[allow(dead_code)]
    fn write_packet(&self, packet: &[u8]) -> nix::Result<usize> {
        // Use nix to write to raw file descriptor
        nix::unistd::write(&self.fd, packet)
    }
}

fn main() {
    let socket = AfPacketSocket::new("veth0").unwrap();
    let mut buffer = [0u8; 1500];

    // Setup ctrl-c handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    while running.load(Ordering::SeqCst) {
        let size = match socket.read_packet(&mut buffer) {
            Ok(size) => size,
            Err(nix::errno::Errno::EAGAIN) => {
                // No data available, sleep for a bit
                // XXX: Obviously, this is not great for performance and we
                // should build an abstraction with epoll or similar.
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            Err(err) => {
                eprintln!("Failed to read packet: {}", err);
                continue;
            }
        };
        let pkt = match SlicedPacket::from_ip(&buffer[..size]) {
            Ok(pkt) => pkt,
            Err(_) => {
                eprintln!("Failed to parse packet of size {}", size);
                continue;
            }
        };

        // Process L3
        let ipv4_slice = match pkt.net {
            Some(NetSlice::Ipv4(ipv4)) => ipv4,
            _ => continue,
        };

        let src_ip = ipv4_slice.header().source_addr();
        let dst_ip = ipv4_slice.header().destination_addr();

        // Process L4
        let icmp = match pkt.transport {
            Some(TransportSlice::Icmpv4(icmp)) => icmp,
            _ => continue,
        };
        println!(
            "ICMP: src_ip: {}, dst_ip: {}, icmp: {:?}",
            src_ip, dst_ip, icmp
        );
    }
}
