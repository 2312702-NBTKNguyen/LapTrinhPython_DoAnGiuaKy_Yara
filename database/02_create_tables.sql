-- Bảng lưu trữ Malware Signatures (Từ API)
CREATE TABLE IF NOT EXISTS malware_signatures (
	id SERIAL PRIMARY KEY,
	file_name VARCHAR(255),
	signature VARCHAR(255),
	file_type VARCHAR(50),
	first_seen TIMESTAMP,
	file_type_mime VARCHAR(100),
	md5_hash VARCHAR(32),
	sha1_hash VARCHAR(40),
	sha256_hash VARCHAR(64) NOT NULL UNIQUE,
	sha3_384_hash VARCHAR(96)
);

-- Bảng lưu trữ lịch sử quét
CREATE TABLE IF NOT EXISTS scan_results (
	id SERIAL PRIMARY KEY,
	signature VARCHAR(255),
	file_name VARCHAR(255),
    file_path TEXT,
    sha256_hash VARCHAR(64),
	detection_method VARCHAR(50),
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1
		FROM pg_constraint
		WHERE conname = 'check_method'
		  AND conrelid = 'scan_results'::regclass
	) THEN
		ALTER TABLE scan_results
		ADD CONSTRAINT check_method
		CHECK (detection_method IN ('HASH_MATCH', 'YARA_MATCH', 'CLEAN'));
	END IF;
END
$$;

-- Indexes cho truy vấn malware_signatures
CREATE INDEX IF NOT EXISTS idx_malware_signatures_md5_hash
ON malware_signatures (md5_hash);

CREATE INDEX IF NOT EXISTS idx_malware_signatures_sha1_hash
ON malware_signatures (sha1_hash);

-- Indexes cho truy vấn scan_results
CREATE INDEX IF NOT EXISTS idx_scan_results_sha256_hash
ON scan_results (sha256_hash);

CREATE INDEX IF NOT EXISTS idx_scan_results_detection_method
ON scan_results (detection_method);

CREATE INDEX IF NOT EXISTS idx_scan_results_scan_time
ON scan_results (scan_time);