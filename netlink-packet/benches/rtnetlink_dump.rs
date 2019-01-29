#[macro_use]
extern crate criterion;
extern crate netlink_packet;
extern crate pcap_file;

use criterion::Criterion;
use netlink_packet::{DecodeError, Emitable, NetlinkBuffer, NetlinkMessage, Parseable};
use pcap_file::{PcapReader, PcapWriter};
use std;
use std::fs::File;

fn bench(c: &mut Criterion) {
    println!(
        "{:X?}",
        std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .as_bytes()
    );
    let pcap_reader = PcapReader::new(File::open("data/rtnetlink.pcap").unwrap()).unwrap();
    let packets: Vec<Vec<u8>> = pcap_reader
        .map(|pkt| pkt.unwrap().data.into_owned().to_vec())
        .collect();

    c.bench_function("parse", move |b| {
        b.iter(|| {
            for (i, buf) in packets.iter().enumerate() {
                println!("len = {}, {:02x?}", buf.len(), &buf[16..]);
                let m = <NetlinkBuffer<_> as Parseable<NetlinkMessage>>::parse(
                    &NetlinkBuffer::new(&&buf[16..]),
                )
                .expect(&format!("message {} failed", i));
                println!("{:?}", m);
            }
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
