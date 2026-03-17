-- Chạy bằng psql để \gexec được hỗ trợ.
-- Lệnh này chỉ tạo database khi nó chưa tồn tại.

SELECT 'CREATE DATABASE yara_malware_signatures'
WHERE NOT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = 'yara_malware_signatures'
)\gexec
