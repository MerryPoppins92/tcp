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
    Closed,
    Listen,
    SynRcvd,
    Estab
}

// transmission protoco
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
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
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace { 
                iss, 
                una: iss, 
                nxt: iss + 1, 
                wnd: 10,
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
            }
        };

        // need to start establish
        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(), 
            tcph.source_port(), 
            c.send.iss, // should be random but 0 makes it
            // The number of data octets beginning with the one indicated in the acknowledgment field which the sender of this segment is willing to accept.
            c.send.wnd // 
        );
        syn_ack.acknowledgment_number = c.recv.nxt;
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
        syn_ack.syn = true;
        syn_ack.ack = true;
        // we create our ip header so we are the destination of the sender
        let mut ip = etherparse::Ipv4Header::new(
            syn_ack.header_len(),
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
        );
        // the kernel do the checksum for us
        // syn_ack.checksum = syn_ack.calc_checksum_ipv4(&ip, &[]).expect("failed to compute checksum");
        // {:02x} from 0 to 255 -> 00 to ff
        eprintln!("got ip header:\n{:02x?}", iph);
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
        eprintln!("got tcp header:\n{:02x?}", tcph);
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
        let unwritten = {
            let mut unwritten = &mut buf[..];
            // Writes a given IPv4 header to the current position (write into unwritten)
            ip.write(&mut unwritten);
            // same as ip
            syn_ack.write(&mut unwritten);
            // how much space is remaining
            unwritten.len()
        };
        eprintln!("responding with {:02x?}", &buf[..buf.len() - unwritten]); // buf.len() - unwritten buffer size minus whats not written
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
        nic.send(&buf[..unwritten])?;
        Ok(Some(c))
        
    }
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8]
    ) -> io::Result<()> {
        match self.state {
            State::SynRcvd => {

            }
            State::Estab => {

            }
            _ => {}
        }
        Ok(())
    }
    // _ => { Ok(1)}
}
        
//     } 
// }