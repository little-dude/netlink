#[macro_use]
extern crate criterion;
extern crate netlink_packet_core;
extern crate netlink_packet_route;
extern crate pcap_file;

use criterion::Criterion;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::RtnlMessage;
use pcap_file::PcapReader;
use std;
use std::fs::File;

fn bench(c: &mut Criterion) {
    let pcap_reader = PcapReader::new(File::open("data/rtnetlink.pcap").unwrap()).unwrap();
    let packets: Vec<Vec<u8>> = pcap_reader
        .map(|pkt| pkt.unwrap().data.into_owned().to_vec())
        .collect();

    c.bench_function("parse", move |b| {
        b.iter(|| {
            for (i, buf) in packets.iter().enumerate() {
                NetlinkMessage::<RtnlMessage>::deserialize(&buf[16..])
                    .expect(&format!("message {} failed", i));
            }
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
