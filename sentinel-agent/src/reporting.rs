use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aya::maps::RingBuf;
use aya::Ebpf;
use clickhouse::Row;
use serde::{Deserialize, Serialize};

use sentinel_ebpf_common::PacketEvent;

#[derive(Debug, Row, Serialize, Deserialize)]
struct NetworkLog {
    timestamp: i64,
    source_ip: Ipv4Addr,
    destination_domain: String,
    bytes_transfered: u64,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct AggKey {
    src_ip: u32,
    domain: String,
}

#[derive(Default)]
struct AggValue {
    bytes: u64,
    last_seen: u64,
}

pub async fn start_report_loop(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let map = ebpf.map_mut("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(map)?;

    let ch_client = clickhouse::Client::default()
        .with_url("http://localhost:8123")
        .with_user("sentinel")
        .with_password("sentinel_pass")
        .with_database("sentinel");

    ensure_table_exists(&ch_client).await?;

    let mut buffer: HashMap<AggKey, AggValue> = HashMap::new();
    let flush_interval_secs = 5;
    let mut last_flush = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    loop {
        while let Some(item) = ring_buf.next() {
            if item.len() >= size_of::<PacketEvent>() {
                let event: PacketEvent = unsafe { (item.as_ptr() as *const PacketEvent).read() };
                
                let domain_bytes = &event.dst_domain[..event.domain_len as usize];
                let mut domain = String::from_utf8_lossy(domain_bytes).to_string();

                if event.quic_initial == 1 {
                    if let Some(quic_domain) = crate::quic_parser::extract_quic_sni(&event) {
                        domain = quic_domain;
                    }
                }

                let key = AggKey {
                    src_ip: event.src_ip,
                    domain,
                };

                let entry = buffer.entry(key).or_default();
                entry.bytes += event.bytes as u64;
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now - last_flush >= flush_interval_secs {
            if !buffer.is_empty() {
                let _ = flush_to_clickhouse(&ch_client, &buffer).await;
                buffer.clear();
            }
            last_flush = now;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn ensure_table_exists(client: &clickhouse::Client) -> anyhow::Result<()> {
    client
        .query("CREATE DATABASE IF NOT EXISTS sentinel ENGINE = Atomic")
        .execute()
        .await?;

    client
        .query(
            "CREATE TABLE IF NOT EXISTS sentinel.network_logs (
                timestamp DateTime64(3, 'UTC'),
                source_ip IPv4,
                destination_domain String,
                bytes_transfered UInt64
            ) ENGINE = MergeTree()
            ORDER BY (timestamp, source_ip)",
        )
        .execute()
        .await?;

    Ok(())
}

async fn flush_to_clickhouse(
    client: &clickhouse::Client,
    buffer: &HashMap<AggKey, AggValue>,
) -> anyhow::Result<()> {
    let mut insert = client.insert("sentinel.network_logs")?;

    for (key, val) in buffer {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let row = NetworkLog {
            timestamp: ts,
            source_ip: Ipv4Addr::from(key.src_ip.to_be_bytes()),
            destination_domain: key.domain.clone(),
            bytes_transfered: val.bytes,
        };

        insert.write(&row).await?;
    }

    insert.end().await?;
    Ok(())
}
