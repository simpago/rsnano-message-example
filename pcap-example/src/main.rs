use chrono::{DateTime, Utc};
use etherparse::{InternetSlice, SlicedPacket};
use pcap_parser::{
    traits::PcapReaderIterator, LegacyPcapReader, Linktype, PcapBlockOwned, PcapError,
};
use rsnano_messages::{Message, MessageHeader};
use std::{
    fs::File,
    net::IpAddr,
    time::{Duration, SystemTime},
};

fn main() {
    let file = File::open("/home/gustav/code/nano/nano.pcap").unwrap();
    let mut blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, file).unwrap();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        assert_eq!(header.network, Linktype::ETHERNET);
                    }
                    PcapBlockOwned::Legacy(block) => {
                        match SlicedPacket::from_ethernet(block.data) {
                            Ok(packet) => {
                                let (source, target) = match packet.ip.unwrap() {
                                    InternetSlice::Ipv4(header, _ext) => (
                                        IpAddr::V4(header.source_addr()),
                                        IpAddr::V4(header.destination_addr()),
                                    ),
                                    InternetSlice::Ipv6(header, _ext) => (
                                        IpAddr::V6(header.source_addr()),
                                        IpAddr::V6(header.destination_addr()),
                                    ),
                                };
                                let sys_time = SystemTime::UNIX_EPOCH
                                    + Duration::from_secs(block.ts_sec as u64)
                                    + Duration::from_micros(block.ts_usec as u64);
                                let datetime: DateTime<Utc> = sys_time.into();
                                println!("{datetime} source {source} target {target}",);

                                if packet.payload.len() >= MessageHeader::SERIALIZED_SIZE {
                                    let (header_bytes, message_bytes) =
                                        packet.payload.split_at(MessageHeader::SERIALIZED_SIZE);
                                    if let Ok(header) =
                                        MessageHeader::deserialize_slice(header_bytes)
                                    {
                                        let message =
                                            Message::deserialize(message_bytes, &header, 0)
                                                .unwrap();
                                        println!("{:?}", message);
                                    }
                                }
                            }
                            Err(e) => eprintln!("could not parse block #{blocks}: {e:?}"),
                        }
                    }
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
                blocks += 1;
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => reader.refill().unwrap(),
            Err(e) => panic!("error while reading: {e:?}"),
        }
    }

    println!("{blocks} blocks processed");
}
