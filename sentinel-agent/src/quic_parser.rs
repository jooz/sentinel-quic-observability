use ring::{hkdf, hmac};
use tracing::{debug};
use sentinel_ebpf_common::PacketEvent;

// RFC 9001 Section 5.2: Initial Secrets
const QUIC_V1_SALT: [u8; 20] = [
    0xaf, 0xc8, 0x31, 0x23, 0x20, 0x2c, 0x44, 0x02, 0x08, 0xe7, 
    0x70, 0x03, 0x39, 0x09, 0x35, 0x1a, 0x4c, 0x32, 0x46, 0x21,
];

// Draft-29 Salt
const QUIC_DRAFT29_SALT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
    0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
];

// QUIC v2 Salt
const QUIC_V2_SALT: [u8; 20] = [
    0x0a, 0xba, 0x4b, 0xf4, 0x64, 0x24, 0x6c, 0x0b, 0x38, 0xcc,
    0x6c, 0xeb, 0x24, 0xd8, 0xe1, 0xce, 0xa1, 0xd0, 0xb0, 0x15,
];

pub fn extract_quic_sni(event: &PacketEvent) -> Option<String> {
    if event.quic_initial == 0 || event.payload_len < 40 {
        return None;
    }

    let payload = &event.payload[..event.payload_len as usize];
    
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let salt_bytes = match version {
        0x00000001 => &QUIC_V1_SALT,
        0xff00001d => &QUIC_DRAFT29_SALT,
        0x709a50c4 => &QUIC_V2_SALT,
        _ => {
            debug!("Unknown QUIC version: {:#010x}", version);
            return None;
        }
    };
    
    let dcid_len = payload[5] as usize;
    if 6 + dcid_len > payload.len() {
        return None;
    }
    let dcid = &payload[6..6 + dcid_len];

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_bytes);
    let initial_secret = salt.extract(dcid);

    let client_initial_secret = derive_secret(&initial_secret, b"client in")?;
    let hp_key_bytes = derive_secret(&client_initial_secret, b"quic hp")?;
    let aead_key_bytes = derive_secret(&client_initial_secret, b"quic key")?;
    let iv_bytes = derive_secret(&client_initial_secret, b"quic iv")?;

    decrypt_payload(payload, &aead_key_bytes, &iv_bytes, &hp_key_bytes)
}

fn derive_secret(secret: &hkdf::Prk, label: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; 32];
    let info = [label];
    secret.expand(&info, CustomLen(32)).ok()?.fill(&mut out).ok()?;
    Some(out)
}

struct CustomLen(usize);
impl hkdf::KeyType for CustomLen {
    fn len(&self) -> usize { self.0 }
}

fn decrypt_payload(raw: &[u8], key: &[u8], iv: &[u8], hp: &[u8]) -> Option<String> {
    let mut pos = 5; 
    let dcid_len = raw[pos] as usize;
    pos += 1 + dcid_len;
    let scid_len = raw[pos] as usize;
    pos += 1 + scid_len;

    let (_, token_var_len) = read_varint(&raw[pos..])?;
    let (token_len, _) = read_varint(&raw[pos..])?;
    pos += token_var_len + token_len as usize;

    let (payload_len_from_hdr, len_var_len) = read_varint(&raw[pos..])?;
    pos += len_var_len;

    let pn_offset = pos;
    let sample_offset = pn_offset + 4; 
    if sample_offset + 16 > raw.len() { return None; }
    let sample = &raw[sample_offset..sample_offset + 16];

    use ring::aead::quic::HeaderProtectionKey;
    let hp_key = HeaderProtectionKey::new(&ring::aead::quic::AES_128, hp).ok()?;
    let mask = hp_key.new_mask(sample).ok()?;

    let mut header = raw[..pn_offset + 4].to_vec();
    header[0] ^= mask[0] & 0x0F; 
    let pn_len = (header[0] & 0x03) as usize + 1;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[i + 1];
    }

    let pn = match pn_len {
        1 => header[pn_offset] as u64,
        2 => u16::from_be_bytes([header[pn_offset], header[pn_offset+1]]) as u64,
        _ => return None,
    };

    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&iv[..4]);
    let pn_bytes = pn.to_be_bytes();
    for i in 0..8 {
        nonce[4+i] = iv[4+i] ^ pn_bytes[i];
    }

    let ciphertext_start = pn_offset + pn_len;
    let ciphertext_len = payload_len_from_hdr as usize - pn_len;
    if ciphertext_start + ciphertext_len > raw.len() { return None; }
    let mut ciphertext = raw[ciphertext_start..ciphertext_start + ciphertext_len].to_vec();

    use ring::aead::{Aad, LessSafeKey, UnboundKey, AES_128_GCM, NONCE_LEN};
    let unbound_key = UnboundKey::new(&AES_128_GCM, key).ok()?;
    let less_safe_key = LessSafeKey::new(unbound_key);
    
    let aad = Aad::from(&header[..ciphertext_start]);
    let decrypted = less_safe_key.open_in_place(ring::aead::Nonce::assume_unique_for_key(nonce), aad, &mut ciphertext).ok()?;

    parse_crypto_frame(decrypted)
}

fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() { return None; }
    let first = data[0];
    let prefix = first >> 6;
    let val = (first & 0x3F) as u64;
    match prefix {
        0 => Some((val, 1)),
        1 => {
            if data.len() < 2 { return None; }
            Some(((val << 8) | data[1] as u64, 2))
        }
        2 => {
            if data.len() < 4 { return None; }
            let v = u32::from_be_bytes([first & 0x3F, data[1], data[2], data[3]]) as u64;
            Some((v, 4))
        }
        _ => None,
    }
}

fn parse_crypto_frame(data: &[u8]) -> Option<String> {
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0x01 && data[i+1] == 0x00 { 
            let mut pos = i + 38; 
            if pos >= data.len() { continue; }
            let suites_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
            pos += 2 + suites_len;
            if pos >= data.len() { continue; }
            let comp_len = data[pos] as usize;
            pos += 1 + comp_len;
            if pos >= data.len() { continue; }
            let ext_total_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
            pos += 2;
            let ext_end = pos + ext_total_len;
            while pos + 4 <= ext_end && pos + 4 <= data.len() {
                let ext_type = u16::from_be_bytes([data[pos], data[pos+1]]);
                let ext_len = u16::from_be_bytes([data[pos+2], data[pos+3]]) as usize;
                pos += 4;
                if ext_type == 0x0000 { 
                    if pos + 5 <= data.len() {
                        let name_len = u16::from_be_bytes([data[pos+3], data[pos+4]]) as usize;
                        if pos + 5 + name_len <= data.len() {
                            return Some(String::from_utf8_lossy(&data[pos+5..pos+5+name_len]).to_string());
                        }
                    }
                }
                pos += ext_len;
            }
        }
    }
    None
}
