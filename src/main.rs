// extern crate tun_tap;
use std::io;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use tcp::{State, Connection};

mod tcp;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src:  (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()>{
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    // Tun Interface
    let mut  nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;

    let mut buf = [0u8; 1504];
    loop {
        // receive message
        let nbytes = nic.recv(&mut buf[..])?;
        // if s/without_packet_info/new/:
        // // be bytes endianness => address location
        // let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        // // 800: ipv4, 86dd: ipv6
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        // if eth_proto != 0x0800 {
        //     continue;
        // }
        // and also  include on send

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                let proto = iph.protocol();

                if proto != 0x06 {
                    // if not a tcp packet
                    continue;
                }
                // let ip_hdr_sz = iph.slice().len(); // size of ip header
                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        use std::collections::hash_map::Entry;
                        let datai = iph.slice().len() + tcph.slice().len(); // the data starts after ip and tcp header

                        match connections.entry(Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        }){
                            Entry::Occupied(mut c) => {
                                c.get_mut().on_packet(&mut nic,iph, tcph, &buf[datai..nbytes])?;
                            },
                            Entry::Vacant(e) => {
                                if let Some(c) = tcp::Connection::accept(
                                    &mut nic,
                                    iph,
                                    tcph,
                                    &buf[datai..nbytes]
                                )? {
                                    e.insert(c);
                                }
                            }
                        }
                        
                        
                        
                    //     eprintln!("{} → {} {}b of tcp port {:x} ", 
                    //     src, 
                    //     dst, 
                    //     tcph.slice().len(), 
                    //     tcph.destination_port());
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet {:?}", e);
                    }
                }

                // eprintln!("{} → {} {}b of protocol {:x} ", src, dst, p.payload_len(), proto)
                // eprintln!("read {} bytes(flags: {:x}, proto: {:x}): {:x?}", nbytes - 4, flags, proto, p);   
            }
            Err(e) => {
                eprintln!("ignoring packet {:?}", e);
            }
        } 
        // :x? ajoute '0x'
            
    }

    Ok(())
}
