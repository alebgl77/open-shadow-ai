CREATE DATABASE IF NOT EXISTS shadai;

CREATE TABLE IF NOT EXISTS shadai.events (
    event_id          UUID DEFAULT generateUUIDv4(),
    timestamp         DateTime64(3, 'UTC'),
    source_type       LowCardinality(String),
    collector_id      String,
    tenant_id         String DEFAULT 'default',
    site_id           String DEFAULT 'default',

    -- Device context
    device_id         String DEFAULT '',
    hostname          String DEFAULT '',

    -- User context
    user_id           String DEFAULT '',
    username          String DEFAULT '',

    -- Network context
    src_ip            String DEFAULT '',
    dst_ip            String DEFAULT '',
    dst_port          UInt16 DEFAULT 0,
    protocol          LowCardinality(String) DEFAULT '',
    domain            String DEFAULT '',
    sni               String DEFAULT '',
    url_host          String DEFAULT '',
    url_path          String DEFAULT '',
    http_method       LowCardinality(String) DEFAULT '',
    bytes_in          UInt64 DEFAULT 0,
    bytes_out         UInt64 DEFAULT 0,

    -- Endpoint context
    process_name      String DEFAULT '',
    process_path      String DEFAULT '',
    parent_process    String DEFAULT '',

    -- Browser context
    browser_name      LowCardinality(String) DEFAULT '',
    extension_id      String DEFAULT '',
    extension_name    String DEFAULT '',

    -- Software/service context
    software_name     String DEFAULT '',
    service_name      String DEFAULT '',
    container_name    String DEFAULT '',
    container_image   String DEFAULT '',
    local_port        UInt16 DEFAULT 0,

    -- OAuth context
    oauth_app_id      String DEFAULT '',
    oauth_app_name    String DEFAULT '',
    oauth_scopes      Array(String) DEFAULT [],

    -- Meta
    raw_ref           String DEFAULT '',
    parser_version    String DEFAULT '',
    normalized_at     DateTime64(3, 'UTC') DEFAULT now64(3),

    -- Matching result (populated by matcher)
    catalog_match_id  String DEFAULT '',
    match_field       LowCardinality(String) DEFAULT '',
    match_confidence  Float32 DEFAULT 0.0
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, source_type)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
