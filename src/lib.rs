// use std::collections::HashMap;
use std::io::prelude::*;
use std::io;
use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::{VecDeque, HashMap};
use std::net::Ipv4Addr;

mod tcp;
use tcp::{State, Connection};

const SENDQUEUE_SIZE: usize = 1024;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src:  (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

// type InterfaceHandle = mpsc::Sender<InterfaceRequest>;
type InterfaceHandle = Arc<Mutex<ConnectionManager>>;

pub struct Interface{
    ih: InterfaceHandle,
    jh: thread::JoinHandle<()>,
}

#[derive(Default)]
struct ConnectionManager {
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
        let ih: InterfaceHandle = Arc::default();

        let jh = {
            let ih = ih.clone();
            thread::spawn(move || {
            // let cm = Arc::new(Mutex::new(ConnectionManager::default()));
            let ih = ih;
            let nic = nic;
            let buf = [0u8; 1504];

            // do the stuff that the main does
         })
        };

        Ok(Interface { ih, jh })
        
    }
    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        use std::collections::hash_map::Entry;
        let mut cm = self.ih.lock().unwrap();
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            },
            Entry::Occupied(_) => {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, "port already bound"));
            }

        }
        // drop
        // drop(cm);
        Ok(TcpListener{port, h: self.ih.clone()})
        // unimplemented!()
    }
    
}

pub struct TcpStream {
    quad: Quad, 
    h: InterfaceHandle
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {  
        let mut cm = self.h.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated unexpectedly"))?;
        
        if c.incoming.is_empty() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no bytesto read"));
        }

        let mut nread = 0;
        let (head, tail) = c.incoming.as_slices();
        let hread = std::cmp::min(buf.len(), head.len());
        buf.copy_from_slice(&head[..hread]);
        nread += hread;
        let tread = std::cmp::min(buf.len() - nread, tail.len());
        buf.copy_from_slice(&tail[..tread]);
        nread += tread;
        Ok(nread)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.h.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated unexpectedly"))?;
        
        if c.unacked.len() >= SENDQUEUE_SIZE {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "too many bytes buffer"));
        }

        let nwrite = std::cmp::min(buf.len(), SENDQUEUE_SIZE - c.unacked.len());
        c.unacked.extend(buf[..nwrite].iter());

        Ok(nwrite)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.h.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated unexpectedly"))?;
        
        if c.unacked.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "too many bytes buffer"))
        }
    }
}

pub struct TcpListener{
    port:u16, 
    h: InterfaceHandle
}

impl TcpListener {
    pub fn try_accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.h.lock().unwrap();
        if let Some(quad) = cm.pending.get_mut(&self.port).expect("port closed while listener still active").pop_front() {
            return Ok(TcpStream{
                quad, 
                h: self.h.clone()
            })
        } else {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no connection to accept"));
        }
    }
}

impl TcpStream {
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        unimplemented!()
    }
}