-- ============================================================================
-- Astra NDR - 0001 core schema
-- Relational state lives in PostgreSQL. High-volume raw telemetry moves to
-- ClickHouse/OpenSearch in Phase 2; normalized_events here stores the working
-- window and is partition-ready (partition by ingest month when volume grows).
-- ============================================================================

-- ------------------------------------------------------------------ sensors
CREATE TABLE IF NOT EXISTS sensor_groups (
    group_id        uuid PRIMARY KEY,
    name            text NOT NULL UNIQUE,
    description     text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sensors (
    sensor_id       uuid PRIMARY KEY,
    name            text NOT NULL UNIQUE,
    description     text NOT NULL DEFAULT '',
    zone            text NOT NULL DEFAULT 'default',
    location        text NOT NULL DEFAULT '',
    group_id        uuid REFERENCES sensor_groups(group_id),
    mode            text NOT NULL DEFAULT 'live_capture',      -- live_capture | cloud_mirror | pcap_replay | log_collection
    version         text NOT NULL DEFAULT '',
    status          text NOT NULL DEFAULT 'enrolling',         -- online | degraded | offline | enrolling | disabled
    api_token_hash  text NOT NULL,                              -- hashed enrollment token, never plaintext
    capabilities    jsonb NOT NULL DEFAULT '{}',
    capture_interfaces text[] NOT NULL DEFAULT '{}',
    tags            text[] NOT NULL DEFAULT '{}',
    enrolled_at     timestamptz NOT NULL DEFAULT now(),
    last_heartbeat  timestamptz,
    config_version  int NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sensor_health (
    id              bigserial PRIMARY KEY,
    sensor_id       uuid NOT NULL REFERENCES sensors(sensor_id) ON DELETE CASCADE,
    sampled_at      timestamptz NOT NULL,
    cpu_percent     double precision NOT NULL DEFAULT 0,
    memory_percent  double precision NOT NULL DEFAULT 0,
    disk_percent    double precision NOT NULL DEFAULT 0,
    interface_up    boolean NOT NULL DEFAULT true,
    packet_drop_percent double precision NOT NULL DEFAULT 0,
    events_per_second   double precision NOT NULL DEFAULT 0,
    buffered_events bigint NOT NULL DEFAULT 0,
    zeek_running    boolean NOT NULL DEFAULT false,
    suricata_running boolean NOT NULL DEFAULT false,
    errors          text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_sensor_health_sensor_time ON sensor_health (sensor_id, sampled_at DESC);

-- ------------------------------------------------------------------- events
CREATE TABLE IF NOT EXISTS raw_event_references (
    raw_ref         text PRIMARY KEY,                           -- e.g. zeek://sensor/conn/abc123
    sensor_id       uuid REFERENCES sensors(sensor_id),
    storage_tier    text NOT NULL DEFAULT 'hot',                -- hot | warm | cold
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS normalized_events (
    event_id        uuid PRIMARY KEY,
    ts              timestamptz NOT NULL,
    observed_time   timestamptz NOT NULL,
    ingest_time     timestamptz NOT NULL DEFAULT now(),
    sensor_id       uuid REFERENCES sensors(sensor_id),
    sensor_name     text NOT NULL DEFAULT '',
    source_zone     text NOT NULL DEFAULT '',
    collector_type  text NOT NULL DEFAULT 'network_sensor',
    category        text NOT NULL,                              -- EventCategory label
    protocol        text NOT NULL DEFAULT '',
    app_protocol    text NOT NULL DEFAULT '',
    src_ip          inet,
    dst_ip          inet,
    src_port        int,
    dst_port        int,
    src_mac         macaddr,
    dst_mac         macaddr,
    hostname        text,
    src_hostname    text,
    dst_hostname    text,
    username        text,
    account_name    text,
    domain_name     text,
    device_id       text,
    asset_id        text,
    user_id         text,
    session_id      text,
    connection_id   text,
    direction       text NOT NULL DEFAULT 'unknown',
    lane            text NOT NULL DEFAULT 'unknown',
    bytes_in        bigint NOT NULL DEFAULT 0,
    bytes_out       bigint NOT NULL DEFAULT 0,
    packets_in      bigint NOT NULL DEFAULT 0,
    packets_out     bigint NOT NULL DEFAULT 0,
    duration_ms     bigint,
    country         text,
    asn             text,
    payload         jsonb NOT NULL DEFAULT '{}',                -- typed protocol payload
    risk_hint       int,
    severity_hint   text,
    confidence_hint int,
    raw_ref         text,
    enrichment      jsonb NOT NULL DEFAULT '{}',
    tags            text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON normalized_events (ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_src ON normalized_events (src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_dst ON normalized_events (dst_ip, ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_category ON normalized_events (category, ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_account ON normalized_events (account_name) WHERE account_name IS NOT NULL;

-- ----------------------------------------------------------------- entities
CREATE TABLE IF NOT EXISTS entities (
    entity_id       uuid PRIMARY KEY,
    entity_type     text NOT NULL,                              -- host | account | domain | ...
    display_name    text NOT NULL,
    canonical_name  text NOT NULL,
    first_seen      timestamptz NOT NULL,
    last_seen       timestamptz NOT NULL,
    last_observed_sensor text,
    identity_confidence int NOT NULL DEFAULT 50,
    criticality     text NOT NULL DEFAULT 'normal',
    business_unit   text,
    owner           text,
    location        text,
    tags            text[] NOT NULL DEFAULT '{}',
    identity_sources text[] NOT NULL DEFAULT '{}',
    behavior_profile jsonb NOT NULL DEFAULT '{}',
    risk_score      int NOT NULL DEFAULT 0,
    urgency_score   int NOT NULL DEFAULT 0,
    threat_score    int NOT NULL DEFAULT 0,
    certainty_score int NOT NULL DEFAULT 0,
    triage_state    text NOT NULL DEFAULT 'untriaged',
    UNIQUE (entity_type, canonical_name)
);
CREATE INDEX IF NOT EXISTS ix_entities_urgency ON entities (urgency_score DESC);

CREATE TABLE IF NOT EXISTS entity_aliases (
    entity_id       uuid NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
    alias           text NOT NULL,
    alias_source    text NOT NULL DEFAULT 'observation',        -- dhcp | dns | ad | manual | ...
    first_seen      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_id, alias)
);

CREATE TABLE IF NOT EXISTS entity_observations (
    id              bigserial PRIMARY KEY,
    entity_id       uuid NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
    observed_at     timestamptz NOT NULL,
    sensor_id       uuid,
    observation     jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_entity_observations ON entity_observations (entity_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS entity_groups (
    group_id        uuid PRIMARY KEY,
    name            text NOT NULL UNIQUE,
    description     text NOT NULL DEFAULT '',
    entity_type     text NOT NULL,
    membership_rule jsonb NOT NULL DEFAULT '{}',                -- static | regex | cidr | ad_import
    importance_weight double precision NOT NULL DEFAULT 1.0,
    is_critical_asset_group boolean NOT NULL DEFAULT false,
    tags            text[] NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS entity_group_members (
    group_id        uuid NOT NULL REFERENCES entity_groups(group_id) ON DELETE CASCADE,
    entity_id       uuid NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
    added_at        timestamptz NOT NULL DEFAULT now(),
    added_by        text NOT NULL DEFAULT 'rule',
    PRIMARY KEY (group_id, entity_id)
);

-- ---------------------------------------------------------------- baselines
CREATE TABLE IF NOT EXISTS baselines (
    baseline_id     uuid PRIMARY KEY,
    scope_type      text NOT NULL,                              -- entity | group | subnet | environment
    scope_id        text NOT NULL,
    metric          text NOT NULL,                              -- e.g. dns_queries_per_hour
    model           text NOT NULL DEFAULT 'ema',                -- ema | zscore | mad | percentile | ...
    state           jsonb NOT NULL DEFAULT '{}',                -- model state (means, windows, decay)
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_type, scope_id, metric)
);

CREATE TABLE IF NOT EXISTS baseline_snapshots (
    id              bigserial PRIMARY KEY,
    baseline_id     uuid NOT NULL REFERENCES baselines(baseline_id) ON DELETE CASCADE,
    taken_at        timestamptz NOT NULL DEFAULT now(),
    state           jsonb NOT NULL
);

-- --------------------------------------------------------------- detections
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id         text PRIMARY KEY,                           -- e.g. c2.beaconing
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    engine_kind     text NOT NULL,                              -- rule | statistical | behavioral | ...
    category        text NOT NULL,
    tactic          text NOT NULL,
    technique_id    text NOT NULL DEFAULT '',
    technique_name  text NOT NULL DEFAULT '',
    kill_chain_stage text NOT NULL DEFAULT '',
    default_severity text NOT NULL DEFAULT 'medium',
    default_confidence int NOT NULL DEFAULT 50,
    enabled         boolean NOT NULL DEFAULT true,
    thresholds      jsonb NOT NULL DEFAULT '{}',
    version         int NOT NULL DEFAULT 1,
    author          text NOT NULL DEFAULT 'astra-core',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS detection_rule_versions (
    rule_id         text NOT NULL REFERENCES detection_rules(rule_id) ON DELETE CASCADE,
    version         int NOT NULL,
    definition      jsonb NOT NULL,
    changed_by      text NOT NULL DEFAULT '',
    changed_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, version)
);

CREATE TABLE IF NOT EXISTS detections (
    detection_id    uuid PRIMARY KEY,
    rule_id         text NOT NULL,
    engine_kind     text NOT NULL,
    title           text NOT NULL,
    summary         text NOT NULL DEFAULT '',
    description     text NOT NULL DEFAULT '',
    category        text NOT NULL,
    tactic          text NOT NULL,
    technique_id    text NOT NULL DEFAULT '',
    technique_name  text NOT NULL DEFAULT '',
    kill_chain_stage text NOT NULL DEFAULT '',
    severity        text NOT NULL,
    confidence      int NOT NULL DEFAULT 0,
    certainty       int NOT NULL DEFAULT 0,
    threat_score    int NOT NULL DEFAULT 0,
    urgency_contribution int NOT NULL DEFAULT 0,
    affected_entity uuid NOT NULL REFERENCES entities(entity_id),
    source_entity   uuid REFERENCES entities(entity_id),
    target_entity   uuid REFERENCES entities(entity_id),
    related_entities uuid[] NOT NULL DEFAULT '{}',
    timeline_start  timestamptz NOT NULL,
    timeline_end    timestamptz NOT NULL,
    baseline_comparisons jsonb NOT NULL DEFAULT '[]',
    why_suspicious  text NOT NULL DEFAULT '',
    false_positive_considerations text[] NOT NULL DEFAULT '{}',
    recommended_investigation_steps text[] NOT NULL DEFAULT '{}',
    recommended_response_actions text[] NOT NULL DEFAULT '{}',
    tuning_fields   jsonb NOT NULL DEFAULT '{}',
    triage_state    text NOT NULL DEFAULT 'untriaged',
    assigned_owner  text,
    status          text NOT NULL DEFAULT 'open',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_detections_entity ON detections (affected_entity, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_detections_status ON detections (status, severity);

CREATE TABLE IF NOT EXISTS detection_evidence (
    id              bigserial PRIMARY KEY,
    detection_id    uuid NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    label           text NOT NULL,
    value           text NOT NULL,
    event_ids       uuid[] NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS detection_tuning (
    id              bigserial PRIMARY KEY,
    rule_id         text NOT NULL REFERENCES detection_rules(rule_id) ON DELETE CASCADE,
    field           text NOT NULL,
    old_value       text,
    new_value       text NOT NULL,
    changed_by      text NOT NULL,
    changed_at      timestamptz NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------------- triage
CREATE TABLE IF NOT EXISTS triage_filters (
    filter_id       uuid PRIMARY KEY,
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    conditions      jsonb NOT NULL,                             -- typed condition tree
    action          text NOT NULL DEFAULT 'suppress_scoring',   -- suppress_scoring | hide | tag
    created_by      text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    enabled         boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS allowlists (
    allowlist_id    uuid PRIMARY KEY,
    name            text NOT NULL,
    kind            text NOT NULL,                              -- ip | cidr | domain | account | ...
    value           text NOT NULL,
    reason          text NOT NULL DEFAULT '',
    created_by      text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz,
    enabled         boolean NOT NULL DEFAULT true
);

-- ---------------------------------------------------------------- incidents
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     uuid PRIMARY KEY,
    title           text NOT NULL,
    summary         text NOT NULL DEFAULT '',
    primary_entity  uuid NOT NULL REFERENCES entities(entity_id),
    severity        text NOT NULL,
    confidence      int NOT NULL DEFAULT 0,
    urgency         int NOT NULL DEFAULT 0,
    kill_chain_stage text NOT NULL DEFAULT '',
    attack_profile  text NOT NULL DEFAULT 'unclassified',
    timeline        jsonb NOT NULL DEFAULT '[]',
    blast_radius    int NOT NULL DEFAULT 0,
    recommended_containment text[] NOT NULL DEFAULT '{}',
    recommended_investigation text[] NOT NULL DEFAULT '{}',
    status          text NOT NULL DEFAULT 'new',
    owner           text,
    sla_deadline    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    exported_to_siem boolean NOT NULL DEFAULT false,
    exported_to_ticketing boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS incident_detections (
    incident_id     uuid NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    detection_id    uuid NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, detection_id)
);

CREATE TABLE IF NOT EXISTS incident_entities (
    incident_id     uuid NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    entity_id       uuid NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
    role            text NOT NULL DEFAULT 'affected',           -- primary | affected | source | target
    PRIMARY KEY (incident_id, entity_id)
);

-- ------------------------------------------------------------- attack graph
CREATE TABLE IF NOT EXISTS attack_graph_nodes (
    node_id         text PRIMARY KEY,
    kind            text NOT NULL,
    label           text NOT NULL,
    entity_id       uuid REFERENCES entities(entity_id),
    risk            int NOT NULL DEFAULT 0,
    tags            text[] NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS attack_graph_edges (
    edge_id         text PRIMARY KEY,
    from_node       text NOT NULL REFERENCES attack_graph_nodes(node_id) ON DELETE CASCADE,
    to_node         text NOT NULL REFERENCES attack_graph_nodes(node_id) ON DELETE CASCADE,
    kind            text NOT NULL,
    label           text NOT NULL DEFAULT '',
    first_seen      timestamptz NOT NULL,
    last_seen       timestamptz NOT NULL,
    weight          double precision NOT NULL DEFAULT 1.0
);
CREATE INDEX IF NOT EXISTS ix_graph_edges_from ON attack_graph_edges (from_node);
CREATE INDEX IF NOT EXISTS ix_graph_edges_to ON attack_graph_edges (to_node);

-- -------------------------------------------------------------- threat intel
CREATE TABLE IF NOT EXISTS threat_feeds (
    feed_id         uuid PRIMARY KEY,
    name            text NOT NULL UNIQUE,
    kind            text NOT NULL DEFAULT 'manual',             -- manual | csv | json | taxii
    url             text,
    status          text NOT NULL DEFAULT 'idle',
    last_update     timestamptz,
    update_history  jsonb NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS threat_indicators (
    indicator_id    uuid PRIMARY KEY,
    indicator       text NOT NULL,
    indicator_type  text NOT NULL,                              -- ip | domain | url | hash
    feed_id         uuid REFERENCES threat_feeds(feed_id),
    actor_label     text,
    tool_label      text,
    campaign_label  text,
    confidence      int NOT NULL DEFAULT 50,
    first_seen      timestamptz NOT NULL DEFAULT now(),
    last_seen       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz,
    enabled         boolean NOT NULL DEFAULT true,
    UNIQUE (indicator, indicator_type)
);
CREATE INDEX IF NOT EXISTS ix_indicators_value ON threat_indicators (indicator);

CREATE TABLE IF NOT EXISTS threat_intel_matches (
    id              bigserial PRIMARY KEY,
    indicator_id    uuid NOT NULL REFERENCES threat_indicators(indicator_id) ON DELETE CASCADE,
    entity_id       uuid REFERENCES entities(entity_id),
    event_id        uuid,
    matched_at      timestamptz NOT NULL DEFAULT now(),
    detection_id    uuid REFERENCES detections(detection_id)
);

-- ----------------------------------------------------------------- response
CREATE TABLE IF NOT EXISTS response_connectors (
    connector_id    uuid PRIMARY KEY,
    name            text NOT NULL UNIQUE,
    kind            text NOT NULL,                              -- webhook | syslog | kafka | siem | soar | edr | firewall
    config          jsonb NOT NULL DEFAULT '{}',                -- no secrets: references env keys
    simulation_mode boolean NOT NULL DEFAULT true,
    status          text NOT NULL DEFAULT 'configured',
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS response_actions (
    action_id       uuid PRIMARY KEY,
    kind            text NOT NULL,                              -- block_ip | block_domain | isolate_host_sim | ...
    reason          text NOT NULL DEFAULT '',
    evidence        jsonb NOT NULL DEFAULT '{}',
    affected_entities uuid[] NOT NULL DEFAULT '{}',
    requested_by    text NOT NULL,
    approved_by     text,
    connector_id    uuid REFERENCES response_connectors(connector_id),
    simulation      boolean NOT NULL DEFAULT true,
    status          text NOT NULL DEFAULT 'pending_approval',   -- pending_approval | approved | executing | completed | failed | rolled_back
    rollback_of     uuid REFERENCES response_actions(action_id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------- notifications
CREATE TABLE IF NOT EXISTS notifications (
    notification_id uuid PRIMARY KEY,
    kind            text NOT NULL,                              -- detection | incident | sensor_health | ...
    severity        text NOT NULL DEFAULT 'info',
    title           text NOT NULL,
    body            text NOT NULL DEFAULT '',
    channel         text NOT NULL DEFAULT 'ui',                 -- ui | email | webhook | syslog | kafka
    related_id      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    read_at         timestamptz
);

-- ------------------------------------------------------------------ hunting
CREATE TABLE IF NOT EXISTS saved_searches (
    search_id       uuid PRIMARY KEY,
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    query           jsonb NOT NULL,                             -- typed query AST
    created_by      text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    schedule_cron   text,                                       -- optional scheduled search
    convert_to_detection boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS custom_models (
    model_id        uuid PRIMARY KEY,
    name            text NOT NULL,
    source_search   uuid REFERENCES saved_searches(search_id),
    definition      jsonb NOT NULL,
    enabled         boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------- notes and audit
CREATE TABLE IF NOT EXISTS analyst_notes (
    note_id         uuid PRIMARY KEY,
    subject_kind    text NOT NULL,                              -- entity | detection | incident
    subject_id      text NOT NULL,
    author          text NOT NULL,
    body            text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_notes_subject ON analyst_notes (subject_kind, subject_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id              bigserial PRIMARY KEY,
    at              timestamptz NOT NULL DEFAULT now(),
    actor           text NOT NULL,                              -- user id / api key id / system
    actor_kind      text NOT NULL DEFAULT 'user',
    action          text NOT NULL,                              -- e.g. triage.close_benign
    subject_kind    text NOT NULL,
    subject_id      text NOT NULL,
    details         jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_audit_at ON audit_logs (at DESC);

-- ----------------------------------------------------------- users and auth
CREATE TABLE IF NOT EXISTS roles (
    role_id         uuid PRIMARY KEY,
    name            text NOT NULL UNIQUE,                       -- admin | analyst | readonly | sensor
    permissions     text[] NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS users (
    user_id         uuid PRIMARY KEY,
    username        text NOT NULL UNIQUE,
    display_name    text NOT NULL DEFAULT '',
    email           text,
    password_hash   text,                                       -- null when SSO-only
    role_id         uuid REFERENCES roles(role_id),
    sso_subject     text,                                       -- external IdP subject for SSO
    disabled        boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_login      timestamptz
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id          uuid PRIMARY KEY,
    name            text NOT NULL,
    key_hash        text NOT NULL,                              -- hashed, never plaintext
    role_id         uuid REFERENCES roles(role_id),
    created_by      uuid REFERENCES users(user_id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz,
    revoked_at      timestamptz
);

-- ----------------------------------------------------------------- settings
CREATE TABLE IF NOT EXISTS settings (
    key             text PRIMARY KEY,                           -- e.g. coverage.internal_cidrs
    value           jsonb NOT NULL,
    updated_by      text NOT NULL DEFAULT 'system',
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- default coverage configuration
INSERT INTO settings (key, value) VALUES
    ('coverage.internal_cidrs', '["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]'),
    ('coverage.excluded_cidrs', '[]'),
    ('retention.normalized_events_days', '30'),
    ('retention.detections_days', '365')
ON CONFLICT (key) DO NOTHING;

-- default roles
INSERT INTO roles (role_id, name, permissions) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'admin',    '{"*"}'),
    ('a0000000-0000-0000-0000-000000000002', 'analyst',  '{"read:*","triage:*","respond:request"}'),
    ('a0000000-0000-0000-0000-000000000003', 'readonly', '{"read:*"}'),
    ('a0000000-0000-0000-0000-000000000004', 'sensor',   '{"ingest:events","ingest:heartbeat"}')
ON CONFLICT (role_id) DO NOTHING;
