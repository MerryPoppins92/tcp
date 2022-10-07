// extern crate tun_tap;
use std::{io, thread};
use std::io::prelude::*;
fn main() -> io::Result<()>{
    let mut i = trust::Interface::new()?;
    let mut l1 = i.bind(1000)?;
    // let mut l2 = i.bind(9001)?;

    let jh1 =thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection fron 7005");
            let n = stream.read(&mut [0]).unwrap();
            eprintln!("read data");
            // assert!(n, 0);
        }
    });

    // let jh2 = thread::spawn(move || {
    //     while let Ok(_stream) = l2.accept() {
    //         eprintln!("got connection fron 9001");
    //     }
    // });
    jh1.join().unwrap();
    // jh2.join().unwrap();
    Ok(())
}
