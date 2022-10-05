// use std::io::prelude::*;
use std::io;



//                         +---------+ ---------\      active OPEN
//                         |  CLOSED |            \    -----------
//                         +---------+ <---------\   \   create TCB
//                            |     ^              \   \  snd SYN
//               passive OPEN |     |   CLOSE        \   \
//               ------------ |     | ----------       \   \
//                create TCB  |     | delete TCB         \   \
//                            V     |                      \   \
//                          +---------+            CLOSE      |    \
//                          |  LISTEN |          ----------    |     |
//                          +---------+          delete TCB     |     |
//               rcv SYN      |     |     SEND                  |     |
//              -----------   |     |    -------                |     V
// +---------+  snd SYN,ACK  /       \   snd SYN              +---------+
// |         |<-----------------           ------------------>|         |
// |   SYN   |                rcv SYN                         |   SYN   |
// |   RCVD  |<-----------------------------------------------|   SENT  |
// |         |                    snd ACK                     |         |
// |         |------------------           -------------------|         |
// +---------+   rcv ACK of SYN \       /  rcv SYN,ACK       +---------+
// |           --------------   |     |   -----------
// |                  x         |     |     snd ACK
// |                            V     V
// |  CLOSE                   +---------+
// | -------                  |  ESTAB  |
// | snd FIN                  +---------+
// |                   CLOSE    |     |    rcv FIN
// V                  -------   |     |    -------
// +---------+        snd FIN  /       \   snd ACK            +---------+
// |  FIN    |<-----------------           ------------------>|  CLOSE  |
// | WAIT-1  |------------------                              |   WAIT  |
// +---------+          rcv FIN  \                            +---------+
// | rcv ACK of FIN   -------   |                            CLOSE  |
// | --------------   snd ACK   |                           ------- |
// V        x                   V                           snd FIN V
// +---------+                  +---------+                   +---------+
// |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
// +---------+                  +---------+                   +---------+
// |                rcv ACK of FIN |                 rcv ACK of FIN |
// |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
// |  -------              x       V    ------------        x       V
// \ snd ACK                 +---------+delete TCB         +---------+
// ------------------------>|TIME WAIT|------------------>| CLOSED  |
//                          +---------+                   +---------+

// TCP Connection State Diagram
//  Figure 6.


pub enum State {
    //Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
}

// transmission protoco
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
}

//   Send Sequence Space

//                    1         2          3          4
//               ----------|----------|----------|----------
//                      SND.UNA    SND.NXT    SND.UNA
//                                           +SND.WND

//         1 - old sequence numbers which have been acknowledged
//         2 - sequence numbers of unacknowledged data
//         3 - sequence numbers allowed for new data transmission
//         4 - future sequence numbers which are not yet allowed

//                           Send Sequence Space

//                                Figure 4.

struct SendSequenceSpace {
    // send unacknowledged
    una: u32,
    // send next
    nxt: u32,
    // send window
    wnd: u16,
    // send urgent pointer
    up: bool,
    // segment sequence number used for last window update
    wl1: usize,
    // segment acknowledgement used for last window update
    wl2: usize,
    // initail send sequence number
    iss: u32,

}

// Receive Sequence Space

// 1          2          3
// ----------|----------|----------
//    RCV.NXT    RCV.NXT
//              +RCV.WND

// 1 - old sequence numbers which have been acknowledged
// 2 - sequence numbers allowed for new reception
// 3 - future sequence numbers which are not yet allowed

//   Receive Sequence Space

//         Figure 5.

struct RecvSequenceSpace {
    // receive next
    nxt: u32,
    // receive window
    wnd: u16,
    // receive urgent pointer
    up: bool,
    // initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        // &mut self,
        nic: &mut tun_tap::Iface, // we can send packets ourself
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        
        // syn() Reads the syn flag (synchronize sequence numbers).
        if !tcph.syn() {
            // only expected Syn packet
            return Ok(None);
        }

        let iss = 0;
        let wnd = 1024;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace { 
                iss, 
                una: iss, 
                nxt: iss, 
                wnd: wnd,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace { 
                // keep track of the sender info
                irs: tcph.sequence_number(), 
                nxt: tcph.sequence_number() + 1, // because we receive the syn
                wnd: tcph.window_size(), 
                up: false
            },
            tcp: etherparse::TcpHeader::new(
                tcph.destination_port(), 
                tcph.source_port(), 
                iss, // should be random but 0 makes it
                // The number of data octets beginning with the one indicated in the acknowledgment field which the sender of this segment is willing to accept.
                wnd, // 
            ),
            ip: etherparse::Ipv4Header::new(
                0,
                64, 
                etherparse::IpTrafficClass::Tcp,
                [ // source: [u8; 4]
                    iph.destination()[0], // pub fn destination(&self) -> &'a [u8]
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            )
        };

        // need to start establish
        
        // syn_ack.acknowledgment_number = c.recv.nxt;
        // 2) A <-- B  ACK your sequence number is X
        // 3) A <-- B  SYN my sequence number is Y
//                        +---------+           
//                        |  LISTEN |          
//                        +---------+          
//                rcv SYN = true|   
//                -----------   |               
// +---------+      snd SYN ,ACK /  => become true
// |         |<-----------------   
// |   SYN   |                                      
// |   RCVD  |
// |         |                   
// |         |   
// +---------+    
        // we create our ip header so we are the destination of the sender

        // {:02x} from 0 to 255 -> 00 to ff
        // eprintln!("got ip header:\n{:02x?}", iph);
        // Ipv4HeaderSlice { slice: [45, 00, 00, 3c, 36, 75, 40, 00, 40, 06, 82, cd, c0, a8, 00, 01, c0, a8, 00, 28] }
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 = 32
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |Vers =4|  IHL=5|TypeofServic=00| Total Length = 00 3c=60bytes  | ihl 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |Identif asembling frag datagram|Flags|      Fragment Offset    | ihl 2
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |  Time to Live |Protocol 06=TCP|         Header Checksum 82, cd|
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    | Source Address c0, a8, 00, 01 192.168.0.1                     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    | Destination Address c0, a8, 00, 28 192.168.0.40               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                    Options                    |    Padding    | ihl 5
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    //                     Example Internet Datagram Header
    
    //                                Figure 4.

    // Various Control Flags.

    // Bit 0: reserved, must be zero
    // Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
    // Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.

    //     0   1   2
    //   +---+---+---+
    //   |   | D | M |
    //   | 0 | F | F |
    //   +---+---+---+
        // eprintln!("got tcp header:\n{:02x?}", tcph);
    // TcpHeaderSlice { slice: [85, 42, 1f, 49, 77, 34, 46, 04, 00, 00, 00, 00, a0, 02, fa, f0, e2, 1e, 00, 00, 02, 04, 05, b4, 04, 02, 08, 0a, db, 48, ac, 69, 00, 00, 00, 00, 01, 03, 03, 07] }
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |Source Port 8542=13366         |Destination Port 1f49=3173     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |         Sequence Number 77, 34, 46, 04,                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |     Acknowledgment Number 00, 00, 00, 00,                     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |  Data |           |U|A|P|R|S|F|                               |
    //    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    //    |    a   |   002    |G|K|H|T|N|N|        fa, f0,                |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |           Checksum e2, 1e     |         Urgent Pointer 0000   |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                    Options                    |    Padding    |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                             data                              |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    //                             TCP Header Format
        //  we want to write in our ip/tcp/payload
        
        // eprintln!("responding with {:02x?}", &buf[..buf.len() - unwritten]); // buf.len() - unwritten buffer size minus whats not written
    // responding with [45, 00, 00, 28, 00, 00, 40, 00, 40, 06, b9, 56, c0, a8, 00, 28, c0, a8, 00, 01, 1f, 49, ae, c0, 00, 00, 00, 00, 20, bb, f0, b7, 50, 12, 00, 0a, 4e, d2, 00, 00]
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |Vers=4|  IHL=5 |TypeofService00|        Total Length 0028=40   |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |         Identification 0000   |Flag4|      Fragment Offset 000|
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |Time to Live40 |    Protocol 06|    Header Checksum b9, 56,    |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                Source Address c0, a8, 00, 28                  |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |            Destination Address  c0, a8, 00, 01,               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                    Options                    |    Padding    |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    //                     Example Internet Datagram Header
        // nic.send(&buf[..buf.len() - unwritten])?;
        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, &[])?;
        Ok(Some(c))
        
    }
    pub fn write(
        &mut self,
        nic: &mut tun_tap::Iface,
        payload: &[u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        // Ok(())
        // self.tcp.rst = true;
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;
        let size = std::cmp::min(buf.len(), 
            self.tcp.header_len() as usize + self.ip.header_len() as usize + payload.len());
        self.ip.set_payload_len(size - self.ip.header_len() as usize);
        // the kernel do the checksum for us
        self.tcp.checksum = self.tcp.calc_checksum_ipv4(&self.ip, &[]).expect("failed to compute checksum");
        //  we want to write in our ip/tcp/payload

        use std::io::Write;
        let mut unwritten = &mut buf[..];
        // Writes a given IPv4 header to the current position (write into unwritten)
        self.ip.write(&mut unwritten);
        // same as ip
        self.tcp.write(&mut unwritten)?;
        let payload_bytes = unwritten.write(payload)?;
        // how much space is remaining
        let unwritten = unwritten.len();
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        nic.send(&buf[..buf.len() - unwritten])?;

        Ok(payload_bytes)

    }
    pub fn send_rst(
        &mut self,
        nic: &mut tun_tap::Iface,
    ) -> io::Result<()> {
        // Ok(())
        self.tcp.rst = true;
        // TODO: fix sequence numbers here
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the same state.
        //
        // TODO: handle synchronized RST
        // 3.  If the connection is in a synchronized state (ESTABLISHED,
        // FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        // any unacceptable segment (out of window sequence number or
        // unacceptible acknowledgment number) must elicit only an empty
        // acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received, and the connection remains in the same state.
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[]);
        Ok(())

    }
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8]
    ) -> io::Result<()> {
        //  first check that sequence numbers are valid (RFC 793 S3.3)
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // BUT REMEMBER WRAPPING
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        };
        if tcph.syn() {
            slen +=1;
        };
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            self.write(nic, &[])?;
            return Ok(());
        }
        self.recv.nxt = seqn.wrapping_add(slen);

        if !tcph.ack() {
            return Ok(());
        }
        let ackn = tcph.acknowledgment_number();
        if let State::SynRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (the SYN).
                self.state = State::Estab;
            } else {
                // TODO: <SEQ=SEG.ACK><CTL=RST>
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                return Ok(());
            }
            self.send.una = ackn;
            // TODO
            assert!(data.is_empty());

            if let State::Estab = self.state {
                // now let's terminate the connection!
                // TODO: needs to be stored in the retransmission queue!
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our FIN has been ACKed!
                eprintln!("they acked our fin");
                self.state = State::FinWait2;
            }
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // we're done with the connection!
                    eprintln!("they fined");
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        Ok(())
        // if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
        //     // return Err(io::Error::new(io::ErrorKind::BrokenPipe, "tried to ack unset byte"));
        //     if !self.state.is_synchroniwed() {
        //         self.send.nxt = tcph.acknowledgment_number();
        //         self.send_rst(nic);
        //     }
        //     return Ok(());
        // }

        // self.send.una = ackn;
        
        // // valide segment check
        // // okay if it acks at leats one bytes, which means that at least one of the following is true
        // // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        


        // if slen == 0 {
        //     // zero-length segment has separate rules for acceptance
        //     if self.recv.wnd == 0 {
        //         if seqn != self.recv.nxt {
        //             return Ok(());
        //         }
        //     } else if !is_between_wrapped(self.recv.nxt.wrapping_add(1), seqn, wend) {
        //             return Ok(());
        //     }
        // } else {
        //     if self.recv.wnd == 0 {
        //         return Ok(());
        //     } else if !is_between_wrapped(self.recv.nxt.wrapping_add(1), seqn, wend) &&
        //         !is_between_wrapped(self.recv.nxt.wrapping_add(1), seqn.wrapping_add(slen - 1), wend)
        //     {
        //         return Ok(());
            
        //     }
        // }
        // if not acceptable send ack
        
        // self.recv.nxt = seqn.wrapping_add(slen);
        // if !tcph.ack() {
        //     return Ok(());
        // }

        // match self.state {
        //     State::SynRcvd => {
        //         if !is_between_wrapped(self.send.una.wrapping_add(1), ackn, self.send.nxt.wrapping_add(1)) {
                    
        //         }
        //         // expect to get an ACK for our SYN
        //         if !tcph.ack() {
        //             return Ok(());
        //         }
        //         // must have ACKed our SYN, sunce we detected at least one acke byte,
        //         // and we have only one byte (the SYN)
        //         self.state = State::Estab;
        //         // now let's termunate the communication
        //         // TODO: needs to be stored into  retransmission queue
        //         self.tcp.fin = true;
        //         self.write(nic, &[])?;
        //         self.state = State::FinWait1;
        //     }
        //     State::Estab => {
        //         unimplemented!();
        //     }
        //     State::FinWait1 => {
        //         if !tcph.fin() || data.is_empty() {
        //             unimplemented!();
        //         }
        //         // must have ACKed our FIN, sunce we detected at least one acke byte,
        //         // and we have only sent one byte (the SYN)
        //         self.state = State::FinWait2;
        //         // self.tcp.fin = false;
        //         // self.write(nic, &[])?;
        //         // self.state = State::Closing;
        //     }
        //     State::FinWait2 => {
        //         if !tcph.fin() || data.is_empty() {
        //             unimplemented!();
        //         }
        //         // must have ACKed our FIN, sunce we detected at least one acke byte,
        //         // and we have only sent one byte (the SYN)
        //         self.tcp.fin = false;
        //         self.write(nic, &[])?;
        //         self.state = State::Closing;
        //     }
        //     _ => {}
        // }
        // Ok(())
    }
    // _ => { Ok(1)}
}
  
fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

// fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
//     use std::cmp::Ordering;
//     match start.cmp(&x) {
//         Ordering::Equal => return false,
//         Ordering::Less => {
//             // check is violated if end is between start and x
//             // we have 
//             // 0 |----------S-----------X----------| (wraparound)
//             // X is between S and E (S < X < E)
//             // 0 |----------S-----------X---E------| (wraparound)
//             // 0 |------E---S-----------X----------| (wraparound)
//             // but NOT in these cases
//             // 0 |----------S----E------X----------| (wraparound)
//             // 0 |----------|-----------X----------| (wraparound)
//             //            ^S=E
//             // 0 |----------S-----------|----------| (wraparound)
//             //                        ^X=E

//             if end >= start && end < x {
//                 return false;
//             } else {
//                 return true;
//             }           
//         },
//         Ordering::Greater => {
//             // check is okay if n is between u and a
//             // check is violated if end is between start and x
//             // we have 
//             // 0 |----------X-----------S----------|
//             // X is between S and E (S < X < E) ONLY in ths case
//             // 0 |----------X-------E---S----------|
//             // but NOT in these cases
//             // 0 |------E---X-----------S----------|
//             // 0 |----------x----------S----E------|
//             // 0 |----------|-----------X----------|
//             //              ^S=E
//             // 0 |----------S-----------|----------|
//             //                          ^X=E
//             // or, in other words iff S < E < X
//             if end < start && end > x {
//                 return true;
//             } else {
//                 return false;
//             }           
//         }
//     }
//     true
// }
// //     if start < x {
// //         // check is violated if end is between start and x
// //         if end >= start && end < x {
// //             return false;
// //         } else {
// //             return true;
// //         }
// //     } else {
// //         // check is okay if n is between u and a
// //         if self.send.nxt >= ackn && self.send.nxt < self.send.una {
// //             return true;
// //         } else {
// //             return false;
// //         }
// //     }
// // }
// //     } 
// // }