-- SQLite schema for YARA malware scanner

CREATE TABLE IF NOT EXISTS malware_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT,
    signature TEXT,
    file_type TEXT,
    first_seen TEXT,
    file_type_mime TEXT,
    md5_hash TEXT,
    sha1_hash TEXT,
    sha256_hash TEXT NOT NULL UNIQUE,
    sha3_384_hash TEXT
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signature TEXT,
    file_name TEXT,
    file_path TEXT,
    sha256_hash TEXT,
    detection_method TEXT CHECK (detection_method IN ('HASH_MATCH', 'YARA_MATCH', 'CLEAN')),
    scan_time TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_malware_signatures_md5_hash
ON malware_signatures (md5_hash);

CREATE INDEX IF NOT EXISTS idx_malware_signatures_sha1_hash
ON malware_signatures (sha1_hash);

CREATE INDEX IF NOT EXISTS idx_scan_results_sha256_hash
ON scan_results (sha256_hash);

CREATE INDEX IF NOT EXISTS idx_scan_results_detection_method
ON scan_results (detection_method);

CREATE INDEX IF NOT EXISTS idx_scan_results_scan_time
ON scan_results (scan_time);
