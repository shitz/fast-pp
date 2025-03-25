use std::{
    io::Write,
    num::NonZeroU32,
    os::unix::prelude::AsRawFd,
    str::FromStr as _,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::Context as _;
use aya::{
    maps::{Array, MapData, XskMap},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use etherparse::*;
use thiserror::Error;
use xsk_rs::{
    config::{BindFlags, FrameSize, Interface, LibxdpFlags, QueueSize, SocketConfig, UmemConfig},
    CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem,
};

use fast_pp_common::{IpNetwork, Ipv4Network, Ipv6Network};

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long, default_value_t = String::from("veth1"))]
    interface: String,
    #[arg(long, default_value_t = 0)]
    queue: u32,
    #[arg(long, default_value_t = ipnet::IpNet::new_assert("192.168.20.0".parse().unwrap(), 24))]
    filter_prefix: ipnet::IpNet,
    #[arg(long, default_value_t = 4096)]
    queue_size: u32,
    #[arg(long, default_value_t = 2048)]
    frame_size: u32,
    #[arg(long, default_value_t = 1<<16)]
    frame_count: u32,
    #[arg(long, default_value_t = 64)]
    batch_size: u32,
    #[arg(long, default_value_t = 10)]
    poll_timeout: u32,
}

pub struct Xsk {
    pub umem: Umem,
    pub fq: FillQueue,
    pub cq: CompQueue,
    pub tx_q: TxQueue,
    pub rx_q: RxQueue,
    pub descs: Vec<FrameDesc>,
}

#[derive(Debug)]
struct Config {
    interface: String,
    queue: u32,
    filter_prefix: ipnet::IpNet,
    xsk: XskConfig,
    batch_size: u32,
    poll_timeout: u32,
}

impl From<Cli> for Config {
    fn from(cli: Cli) -> Self {
        Self {
            interface: cli.interface,
            queue: cli.queue,
            filter_prefix: cli.filter_prefix,
            xsk: XskConfig {
                tx_q_size: QueueSize::new(cli.queue_size).unwrap(),
                rx_q_size: QueueSize::new(cli.queue_size).unwrap(),
                cq_size: QueueSize::new(cli.queue_size).unwrap(),
                fq_size: QueueSize::new(cli.queue_size).unwrap(),
                frame_size: FrameSize::new(cli.frame_size).unwrap(),
                frame_count: cli.frame_count,
            },
            batch_size: cli.batch_size,
            poll_timeout: cli.poll_timeout,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct XskConfig {
    tx_q_size: QueueSize,
    rx_q_size: QueueSize,
    cq_size: QueueSize,
    fq_size: QueueSize,
    frame_size: FrameSize,
    frame_count: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    let cfg = Config::from(cli);

    // Load the eBPF program bytecode.
    // This will include the eBPF object file as raw bytes at compile-time and
    // load it at runtime.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fast-pp"
    )))?;
    // Setup the eBPF logger such that log messages from the eBPF program are
    // accessible in user-space and printed to stdout.
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if log statements are removed from the eBPF program.
        log::warn!("failed to initialize eBPF logger: {}", e);
    }

    // Load the XDP program and attach it to the interface.
    let program: &mut Xdp = ebpf.program_mut("xdp_example").unwrap().try_into()?;
    program.load()?;
    program.attach(&cfg.interface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // Create the Umem and AF_XDP (aka. XSK) Socket configuration.
    let (umem_config, socket_config) = build_umem_and_socket_config(&cfg.xsk);
    let mut xsk = build_socket_and_umem(
        umem_config,
        socket_config,
        NonZeroU32::new(cfg.xsk.frame_count).unwrap(),
        &Interface::from_str(cfg.interface.as_str()).unwrap(),
        cfg.queue,
    );

    // Register the socket with the XskMap such that packets can be redirected
    // to it.
    let xsk_map = ebpf.map_mut("XSK_MAP").context("Failed to get XSK_MAP")?;
    let mut xsk_map = XskMap::try_from(xsk_map)?;
    if let Err(e) = xsk_map.set(cfg.queue, xsk.rx_q.fd().as_raw_fd(), 0) {
        log::error!("Failed to register socket with XskMap: {}", e);
        return Err(e.into());
    }
    log::info!("Registered socket with XskMap");

    let filter_map = ebpf.map_mut("FILTER").context("Failed to get FILTER")?;
    let mut filter_map: Array<&mut MapData, IpNetwork> = Array::try_from(filter_map)?;

    // Add filter prefix to filter map
    let net = match cfg.filter_prefix {
        ipnet::IpNet::V4(prefix) => {
            IpNetwork::V4(Ipv4Network::new(prefix.addr(), prefix.prefix_len()))
        }
        ipnet::IpNet::V6(prefix) => {
            IpNetwork::V6(Ipv6Network::new(prefix.addr(), prefix.prefix_len()))
        }
    };
    if let Err(e) = filter_map.set(0, net, 0) {
        log::error!("Failed to add filter to filter map: {}", e);
        return Err(e.into());
    }

    // Split the frame descriptors into two halves, one for the receiver and one
    // for the sender queues.
    let (rx_descs, tx_descs) = xsk.descs.split_at_mut((cfg.xsk.frame_count / 2) as usize);

    // Populate receiver fill queue to be ready to receive packets
    let frames_filled = unsafe { xsk.fq.produce(&rx_descs[..cfg.xsk.fq_size.get() as usize]) };
    assert_eq!(frames_filled, cfg.xsk.fq_size.get() as usize);
    log::info!("Frames added to receiver fill queue: {}", frames_filled);

    // Setup ctrl-c handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // Poll for packets and print them. Exit when Ctrl-C is received.
    while running.load(Ordering::SeqCst) {
        let frames_rcvd = match unsafe {
            xsk.rx_q.poll_and_consume(
                &mut rx_descs[..cfg.batch_size as usize],
                cfg.poll_timeout as i32,
            )
        } {
            Ok(pkts_rcvd) => pkts_rcvd,
            Err(e) => {
                log::error!("poll_and_consume error: {}", e);
                break;
            }
        };
        if frames_rcvd == 0 {
            // No frames consumed, wake up fill queue if required
            if xsk.fq.needs_wakeup() {
                let fd = xsk.rx_q.fd_mut();
                xsk.fq.wakeup(fd, cfg.poll_timeout as i32).unwrap();
            }
            continue;
        }
        log::debug!("receiver rx queue consumed {} frames", frames_rcvd);
        // Process frames
        for desc in rx_descs.iter().take(frames_rcvd) {
            let data = unsafe { xsk.umem.data(desc) };
            let reply = match process_packet(data.contents()) {
                Ok(reply) => reply,
                Err(e) => {
                    log::error!("Error processing packet: {}", e);
                    continue;
                }
            };

            // Write the reply packet to the tx queue, we always use
            // the first frame desc and poll until it's sent at which point we
            // add it to the fill queue again.
            let tx_desc = tx_descs.first_mut().unwrap();
            unsafe {
                xsk.umem
                    .data_mut(tx_desc)
                    .cursor()
                    .write_all(reply.as_slice())
                    .expect("msg write failed");
            }
            // Wait until we're ok to write
            while !xsk.tx_q.poll(cfg.poll_timeout as i32).unwrap() {
                log::debug!("sender socket not ready to write");
                continue;
            }
            // Send the packet by adding the frame to the tx queue
            while unsafe { xsk.tx_q.produce_one_and_wakeup(tx_desc).unwrap() } != 1 {
                // Loop until frames added to the tx ring.
                log::debug!("sender tx queue failed to allocate");
            }
            log::debug!("submitted 1 frame to sender tx queue");
            // Wait until we can consume the frame
            unsafe {
                while xsk.cq.consume_one(tx_desc) != 1 {
                    log::debug!("sender comp queue failed to consume");
                }
            }
            log::debug!("sender comp queue consumed 1 frame");
        }
        // Add frames back to fill queue
        unsafe {
            let fd = xsk.rx_q.fd_mut();
            xsk.fq
                .produce_and_wakeup(&rx_descs[..frames_rcvd], fd, cfg.poll_timeout as i32)
                .unwrap();
        }
    }

    Ok(())
}

fn process_packet(data: &[u8]) -> Result<Vec<u8>, PacketProcessError> {
    let pkt = match SlicedPacket::from_ethernet(data) {
        Ok(pkt) => Ok(pkt),
        Err(value) => Err(PacketProcessError::ParsingError(value)),
    }?;

    // Process L2
    let eth_slice = match pkt.link {
        Some(LinkSlice::Ethernet2(eth)) => Ok(eth),
        Some(t) => Err(PacketProcessError::UnsupportedL2Type(format!("{:?}", t))),
        None => Err(PacketProcessError::UnsupportedL2Type("none".to_string())),
    }?;
    let src_mac = eth_slice.source();
    let dst_mac = eth_slice.destination();

    // Process L3
    let ipv4_slice = match pkt.net {
        Some(NetSlice::Ipv4(ipv4)) => Ok(ipv4),
        Some(t) => Err(PacketProcessError::UnsupportedL3Type(format!("{:?}", t))),
        None => Err(PacketProcessError::UnsupportedL3Type("none".to_string())),
    }?;

    let src_ip = ipv4_slice.header().source_addr();
    let dst_ip = ipv4_slice.header().destination_addr();

    // Process L4
    let (echo_hdr, echo_pld) = match pkt.transport {
        Some(TransportSlice::Icmpv4(icmp)) => {
            let hdr = match icmp.icmp_type() {
                Icmpv4Type::EchoRequest(hdr) => Ok(hdr),
                _ => Err(PacketProcessError::UnsupportedIcmpType(format!(
                    "{:?}",
                    icmp.icmp_type()
                ))),
            }?;
            log::debug!(
                "ICMP Echo request: src_ip: {}, dst_ip: {}, id: {}, seq: {}",
                src_ip,
                dst_ip,
                hdr.id,
                hdr.seq
            );
            Ok((hdr, icmp.payload()))
        }
        Some(t) => Err(PacketProcessError::UnsupportedL4Type(format!("{:?}", t))),
        None => Err(PacketProcessError::UnsupportedL4Type("none".to_string())),
    }?;

    // Build ICMP Echo reply
    let builder = PacketBuilder::ethernet2(dst_mac, src_mac)
        .ipv4(dst_ip.octets(), src_ip.octets(), 64)
        .icmpv4_echo_reply(echo_hdr.id, echo_hdr.seq);
    let mut send_buf = Vec::<u8>::with_capacity(builder.size(echo_pld.len()));
    builder.write(&mut send_buf, echo_pld).unwrap();

    log::debug!(
        "ICMP Echo reply: src_ip: {}, dst_ip: {}, id: {}, seq: {}",
        dst_ip,
        src_ip,
        echo_hdr.id,
        echo_hdr.seq
    );

    Ok(send_buf)
}

fn build_umem_and_socket_config(config: &XskConfig) -> (UmemConfig, SocketConfig) {
    let umem_config = UmemConfig::builder()
        .frame_size(config.frame_size)
        .fill_queue_size(config.fq_size)
        .comp_queue_size(config.cq_size)
        .build()
        .unwrap();

    let socket_config = SocketConfig::builder()
        .rx_queue_size(config.rx_q_size)
        .tx_queue_size(config.tx_q_size)
        .libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD)
        .bind_flags(BindFlags::XDP_USE_NEED_WAKEUP)
        .build();

    (umem_config, socket_config)
}

pub fn build_socket_and_umem(
    umem_config: UmemConfig,
    socket_config: SocketConfig,
    frame_count: NonZeroU32,
    if_name: &Interface,
    queue_id: u32,
) -> Xsk {
    let (umem, descs) = Umem::new(umem_config, frame_count, false).expect("failed to build umem");

    // Bind an AF_XDP socket to if_name and queue_id
    let (tx_q, rx_q, fq_and_cq) = unsafe {
        Socket::new(socket_config, &umem, if_name, queue_id).expect("failed to build socket")
    };

    let (fq, cq) = fq_and_cq.unwrap_or_else(|| {
        panic!(
            "missing fill and comp queue - interface {:?} may already be bound to",
            if_name
        )
    });

    Xsk {
        umem,
        fq,
        cq,
        tx_q,
        rx_q,
        descs,
    }
}

#[derive(Error, Debug)]
enum PacketProcessError {
    #[error("parsing error: {0}")]
    ParsingError(#[from] etherparse::err::packet::SliceError),
    #[error("unsupported l2 type: {0}")]
    UnsupportedL2Type(String),
    #[error("unsupported l3 type: {0}")]
    UnsupportedL3Type(String),
    #[error("unsupported l4 type: {0}")]
    UnsupportedL4Type(String),
    #[error("unsupported ICMP type: {0}")]
    UnsupportedIcmpType(String),
}
