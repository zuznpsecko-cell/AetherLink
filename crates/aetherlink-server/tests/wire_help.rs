//! Shared wire helpers: sealed-frame read/write over any stream.
#![allow(dead_code)]

use std::io::{Read, Write};

use aetherlink_frame::codec::FrameHeader;
use bytes::BytesMut;

/// Read one sealed frame (24B header + ciphertext).
pub fn read_frame<S: Read>(stream: &mut S) -> (FrameHeader, Vec<u8>) {
    let mut hb = [0u8; aetherlink_frame::FRAME_HEADER_SIZE];
    stream.read_exact(&mut hb).expect("read header");
    let mut buf = BytesMut::from(&hb[..]);
    let header = FrameHeader::decode(&mut buf).expect("decode header");
    let mut ct = vec![0u8; header.length as usize];
    stream.read_exact(&mut ct).expect("read ciphertext");
    (header, ct)
}

/// Write one sealed frame.
pub fn write_frame<S: Write>(stream: &mut S, header: &FrameHeader, ct: &[u8]) {
    let mut buf = BytesMut::new();
    header.encode(&mut buf);
    stream.write_all(&buf).expect("write header");
    stream.write_all(ct).expect("write ciphertext");
    stream.flush().expect("flush");
}
