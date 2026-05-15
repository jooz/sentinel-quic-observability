#![no_std]

use core::mem;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PacketEvent {
    pub src_ip: u32,
    pub dst_domain: [u8; 64],
    pub domain_len: u16,
    pub bytes: u32,
    pub timestamp_ns: u64,
    pub quic_initial: u8,
    pub payload_len: u16,
    pub payload: [u8; 1500],
}

impl PacketEvent {
    pub fn new() -> Self {
        Self {
            src_ip: 0,
            dst_domain: [0u8; 64],
            domain_len: 0,
            bytes: 0,
            timestamp_ns: 0,
            quic_initial: 0,
            payload_len: 0,
            payload: [0u8; 1500],
        }
    }
}

const _: () = {
    let _ = mem::size_of::<PacketEvent>();
};
