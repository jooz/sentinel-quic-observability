CREATE DATABASE IF NOT EXISTS sentinel ENGINE = Atomic;

CREATE TABLE IF NOT EXISTS sentinel.network_logs (
    timestamp DateTime64(3, 'UTC'),
    source_ip IPv4,
    destination_domain String,
    bytes_transfered UInt64
) ENGINE = MergeTree()
ORDER BY (timestamp, source_ip)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;
