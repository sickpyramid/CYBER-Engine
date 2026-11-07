-- CyberAgent historical-attack corpus schema
-- One normalized store for every ingested historical exploit, across sources & chains.

CREATE TABLE IF NOT EXISTS attacks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT NOT NULL,          -- defihacklabs | reentrancy_list | slowmist | rekt | manual
    source_ref      TEXT,                   -- file path or URL it came from
    uid             TEXT UNIQUE,            -- stable dedupe key (source + normalized name + date)
    name            TEXT,                   -- protocol / incident name
    protocol        TEXT,
    chain           TEXT,                   -- ethereum | bsc | polygon | arbitrum | optimism | solana | ...
    occurred_date   TEXT,                   -- YYYY-MM or YYYY-MM-DD
    occurred_year   INTEGER,
    loss_usd        REAL,                   -- best-effort parsed USD loss
    vuln_class      TEXT,                   -- normalized taxonomy slug (see vuln_taxonomy)
    vuln_raw        TEXT,                   -- raw vuln text as found
    attacker_addrs  TEXT,                   -- json array
    victim_addrs    TEXT,                   -- json array
    attack_txs      TEXT,                   -- json array of tx hashes
    block_number    INTEGER,                -- replay fork block (N-1 of first attack tx), when known
    refs            TEXT,                   -- json array of reference URLs
    poc_lang        TEXT,                   -- solidity | rust | none
    poc_code        TEXT,                   -- the actual reproduction code (the attack *sequence*)
    summary         TEXT,                   -- short human summary
    raw_header      TEXT,                   -- original header/comment block
    multi_stage     INTEGER DEFAULT 0,      -- heuristic: involves >1 tx / flashloan / cross-contract
    ingested_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_attacks_chain  ON attacks(chain);
CREATE INDEX IF NOT EXISTS idx_attacks_vuln   ON attacks(vuln_class);
CREATE INDEX IF NOT EXISTS idx_attacks_year   ON attacks(occurred_year);

-- Decomposed attack sequence (filled by the enrichment pass / LLM extraction).
CREATE TABLE IF NOT EXISTS attack_steps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_id   INTEGER NOT NULL REFERENCES attacks(id) ON DELETE CASCADE,
    step_no     INTEGER,
    actor       TEXT,       -- attacker | victim_contract | flashloan_provider | oracle | ...
    action      TEXT,       -- what happens in this step
    primitive   TEXT        -- flashloan | reentrancy | price_manip | approval_abuse | ...
);
CREATE INDEX IF NOT EXISTS idx_steps_attack ON attack_steps(attack_id);

-- Canonical vulnerability taxonomy (stable slugs the model learns to emit).
CREATE TABLE IF NOT EXISTS vuln_taxonomy (
    slug        TEXT PRIMARY KEY,
    label       TEXT,
    chain_scope TEXT,       -- evm | solana | both
    description TEXT
);

-- Provenance / run log so re-ingests are auditable.
CREATE TABLE IF NOT EXISTS ingest_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT,
    started_at  TEXT,
    finished_at TEXT,
    rows_added  INTEGER,
    notes       TEXT
);
