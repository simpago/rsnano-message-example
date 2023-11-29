use rsnano_messages::{Message, MessageHeader};

fn main() {
    // These are the bytes of the header and the message
    // They could come from a pcap file for example
    let buffer = [
        82, 67, 19, 19, 18, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 10, 0, 0, 0, 5, 0, 0, 0,
    ];

    let (header_bytes, message_bytes) = buffer.split_at(MessageHeader::SERIALIZED_SIZE);
    let header = MessageHeader::deserialize_slice(header_bytes).unwrap();
    let message = Message::deserialize(message_bytes, &header, 0).unwrap();

    println!("deserialized header: {header:?}");
    println!("deserialized message: {message:?}");
}
