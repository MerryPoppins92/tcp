// extern crate tun_tap;
use std::{io, thread};
use std::io::prelude::*;
fn main() -> io::Result<()>{
    let x = 1000;
    let mut i = trust::Interface::new()?;
    let mut l1 = i.bind(x)?;
    // let mut l2 = i.bind(9001)?;

    let jh1 =thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection from {x}");
            loop {
                let mut buf = [0; 512];
                
                let n = stream.read(&mut buf[..]).unwrap();
                eprintln!("read data {n}b of data");
                if n == 0 {
                    eprintln!("no more data");
                    break;
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }

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
