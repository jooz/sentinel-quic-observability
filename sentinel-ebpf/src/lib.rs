#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
    EbpfContext,
};

use sentinel_ebpf_common::PacketEvent;

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(524288, 0);

#[classifier]
pub fn sentinel_tc(ctx: TcContext) -> i32 {
    match try_sentinel_tc(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

fn try_sentinel_tc(ctx: TcContext) -> Result<i32, i64> {
    let eth_type = ctx.load::<u16>(12).map_err(|e| e as i64)?;
    if u16::from_be(eth_type) != 0x0800 {
        return Ok(TC_ACT_OK);
    }

    let ip_proto = ctx.load::<u8>(23).map_err(|e| e as i64)?;
    if ip_proto != 6 && ip_proto != 17 {
        return Ok(TC_ACT_OK);
    }

    let ip_hl_raw = ctx.load::<u8>(14).map_err(|e| e as i64)?;
    let ip_hl = (ip_hl_raw & 0x0F) as usize * 4;
    let src_ip = ctx.load::<u32>(26).map_err(|e| e as i64)?;
    let l4_off = 14 + ip_hl;
    let dst_port = u16::from_be(ctx.load::<u16>(l4_off + 2).map_err(|e| e as i64)?);

    if dst_port != 443 {
        return Ok(TC_ACT_OK);
    }

    if let Some(mut entry) = RING_BUF.reserve::<PacketEvent>(0) {
        let event = unsafe { &mut *(entry.as_mut_ptr() as *mut PacketEvent) };
        // Zero out the struct since reserve does not guarantee zeroed memory
        *event = PacketEvent::new();
        
        event.src_ip = src_ip;
        event.bytes = ctx.len() as u32;
        event.timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

        let mut domain_found = false;
        if ip_proto == 6 {
            // TCP Logic (TLS SNI)
            if let Ok(tcp_offset_raw) = ctx.load::<u8>(l4_off + 12) {
                let tcp_hl = ((tcp_offset_raw >> 4) & 0x0F) as usize * 4;
                let payload_offset = l4_off + tcp_hl;

                if let Ok(sni_bytes) = extract_sni(&ctx, payload_offset) {
                    let len = sni_bytes.len().min(63);
                    event.dst_domain[..len].copy_from_slice(&sni_bytes[..len]);
                    event.domain_len = len as u16;
                    domain_found = true;
                }
            }
        } else if ip_proto == 17 {
            // UDP Logic (QUIC Initial Packet Detection)
            if let Ok(first_byte) = ctx.load::<u8>(l4_off + 8) {
                // QUIC Long Header: bit 7 is 1. Initial Packet Type: bits 4-5 are 00.
                if (first_byte & 0x80) != 0 && (first_byte & 0x30) == 0 {
                    event.quic_initial = 1;
                    let payload_offset = l4_off + 8;
                    let pkt_len = ctx.len() as usize;
                    if pkt_len > payload_offset {
                        let mut len = pkt_len - payload_offset;
                        if len > 1500 {
                            len = 1500;
                        }
                        
                        let safe_len = len & 0x7FF;
                        if safe_len > 0 && safe_len <= 1500 {
                            unsafe {
                                let _ = aya_ebpf::helpers::bpf_skb_load_bytes(
                                    ctx.as_ptr(),
                                    payload_offset as u32,
                                    event.payload.as_mut_ptr() as *mut _,
                                    safe_len as u32,
                                );
                            }
                            event.payload_len = safe_len as u16;
                        }
                    }
                }
            }
        }

        if !domain_found {
            let (label, label_len) = if ip_proto == 17 {
                (b"unknown (quic)" as &[u8], 14)
            } else {
                (b"unknown" as &[u8], 7)
            };
            let len = label_len.min(63);
            event.dst_domain[..len].copy_from_slice(&label[..len]);
            event.domain_len = len as u16;
        }
        entry.submit(0);
    }

    Ok(TC_ACT_OK)
}

fn extract_sni(ctx: &TcContext, payload_off: usize) -> Result<[u8; 64], i64> {
    let mut sni = [0u8; 64];

    let content_type = ctx.load::<u8>(payload_off).map_err(|e| e as i64)?;
    if content_type != 0x16 {
        return Err(-1);
    }

    let tls_len = u16::from_be(ctx.load::<u16>(payload_off + 3).map_err(|e| e as i64)?) as usize;
    if tls_len < 40 || tls_len > 4096 {
        return Err(-1);
    }

    let hs_off = payload_off + 5;
    let hs_type = ctx.load::<u8>(hs_off).map_err(|e| e as i64)?;
    if hs_type != 0x01 {
        return Err(-1);
    }

    let session_id_off = hs_off + 38;
    let session_id_len = ctx.load::<u8>(session_id_off).map_err(|e| e as i64)? as usize;

    let cipher_off = session_id_off + 1 + session_id_len;
    let cipher_len = u16::from_be(ctx.load::<u16>(cipher_off).map_err(|e| e as i64)?) as usize;

    let compress_off = cipher_off + 2 + cipher_len;
    let compress_len = ctx.load::<u8>(compress_off).map_err(|e| e as i64)? as usize;

    let extensions_off = compress_off + 1 + compress_len;
    let ext_total_len =
        u16::from_be(ctx.load::<u16>(extensions_off).map_err(|e| e as i64)?) as usize;

    let mut ext_pos = extensions_off + 2;
    let mut remaining = ext_total_len;

    for _ in 0..24 {
        if remaining < 4 {
            break;
        }

        let ext_type = u16::from_be(ctx.load::<u16>(ext_pos).map_err(|e| e as i64)?);
        let ext_len =
            u16::from_be(ctx.load::<u16>(ext_pos + 2).map_err(|e| e as i64)?) as usize;
        ext_pos += 4;
        remaining -= 4;

        if ext_type == 0x0000 {
            if ext_len < 5 {
                break;
            }

            let sni_type = ctx.load::<u8>(ext_pos + 2).map_err(|e| e as i64)?;
            if sni_type != 0x00 {
                break;
            }

            let name_len =
                u16::from_be(ctx.load::<u16>(ext_pos + 3).map_err(|e| e as i64)?) as usize;
            if name_len > 63 || name_len == 0 {
                break;
            }

            let name = ctx
                .load::<[u8; 64]>(ext_pos + 5)
                .map_err(|e| e as i64)?;
            sni[..name_len].copy_from_slice(&name[..name_len]);

            return Ok(sni);
        }

        ext_pos += ext_len;
        if remaining >= ext_len {
            remaining -= ext_len;
        } else {
            break;
        }
    }

    Err(-1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
