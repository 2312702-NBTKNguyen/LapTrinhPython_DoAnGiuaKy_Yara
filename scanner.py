import os
import hashlib
import psycopg2
import yara
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

class MalwareScanner:
    def __init__(self, rules_path='rules/index.yar'):
        self.db_conn = self._connect_db()
        self.yara_rules = self._load_yara_rules(rules_path)
        
        # Thống kê kết quả cho báo cáo
        self.stats = {'scanned': 0, 'hash_match': 0, 'yara_match': 0, 'clean': 0, 'errors': 0}

    def _connect_db(self):
        """Khởi tạo kết nối đến PostgreSQL"""
        try:
            conn = psycopg2.connect(
                host=os.getenv("DB_HOST", "localhost"),
                port=os.getenv("DB_PORT", "5432"),
                database=os.getenv("DB_NAME"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD")
            )
            print("[+] Đã kết nối Database thành công.")
            return conn
        except Exception as e:
            print(f"[-] Lỗi kết nối Database: {e}")
            exit(1)

    def _load_yara_rules(self, rules_path):
        """Biên dịch YARA rules MỘT LẦN duy nhất vào RAM để tối ưu tốc độ quét"""
        if not os.path.exists(rules_path):
            print(f"[-] Không tìm thấy file luật: {rules_path}")
            exit(1)
        try:
            print(f"[*] Đang biên dịch bộ luật YARA từ {rules_path}...")
            rules = yara.compile(filepath=rules_path)
            print("[+] Nạp YARA rules thành công!")
            return rules
        except yara.SyntaxError as e:
            print(f"[-] Lỗi cú pháp trong file YARA: {e}")
            exit(1)

    def calculate_sha256(self, filepath):
        """Tính mã băm SHA256 của file bằng cách đọc từng chunk để tránh tràn RAM"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                # Đọc từng khối 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"[-] Không thể đọc file {filepath}: {e}")
            return None

    def check_hash_in_db(self, file_hash):
        # Truy vấn Lớp 1: Kiểm tra hash trong SQL
        try:
            cursor = self.db_conn.cursor()
            query = "SELECT file_name, signature FROM malware_signatures.malware_signatures WHERE sha256_hash = %s;"
            cursor.execute(query, (file_hash,))
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                # Trả về Tên Malware và họ (Signature)
                return f"{result[0]} ({result[1]})"
            return None
        except Exception as e:
            print(f"[-] Lỗi truy vấn Database: {e}")
            self.db_conn.rollback()
            return None

    def scan_with_yara(self, filepath):
        """Truy vấn Lớp 2: Quét file bằng engine YARA"""
        try:
            matches = self.yara_rules.match(filepath)
            if matches:
                # Lấy tên của tất cả các rule bị vi phạm ghép lại
                detected_rules = ", ".join([match.rule for match in matches])
                return detected_rules
            return None
        except Exception as e:
            # Fallback đọc bytes để tránh lỗi mở file theo đường dẫn Unicode trên Windows.
            try:
                with open(filepath, "rb") as f:
                    file_data = f.read()
                matches = self.yara_rules.match(data=file_data)
                if matches:
                    detected_rules = ", ".join([match.rule for match in matches])
                    return detected_rules
                return None
            except Exception as fallback_error:
                print(f"[-] Lỗi khi YARA quét file {filepath}: {fallback_error}")
                return "__SCAN_ERROR__"

    def log_scan_result(self, filename, filepath, filehash, detection_method, malware_name):
        """Lưu lịch sử quét vào bảng scan_results"""
        try:
            cursor = self.db_conn.cursor()
            query = """
                INSERT INTO malware_signatures.scan_results (file_name, file_path, sha256_hash, detection_method, signature)
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (filename, filepath, filehash, detection_method, malware_name))
            self.db_conn.commit()
            cursor.close()
        except Exception as e:
            print(f"[-] Lỗi lưu lịch sử: {e}")
            self.db_conn.rollback()

    def scan_target(self, target_path):
        """Hàm chính điều phối luồng quét cho 1 file cụ thể"""
        self.stats['scanned'] += 1
        filename = os.path.basename(target_path)
        
        # 1. Tính Hash
        file_hash = self.calculate_sha256(target_path)
        if not file_hash:
            self.stats['errors'] += 1
            return

        # 2. Fast Path: Check Hash Database
        db_match = self.check_hash_in_db(file_hash)
        if db_match:
            print(f"[!] DANGER (HASH_MATCH): {filename} -> {db_match}")
            self.log_scan_result(filename, target_path, file_hash, "HASH_MATCH", db_match)
            self.stats['hash_match'] += 1
            return

        # 3. Deep Path: YARA Scan (chỉ chạy khi Hash không khớp)
        yara_match = self.scan_with_yara(target_path)
        if yara_match == "__SCAN_ERROR__":
            self.stats['errors'] += 1
            return
        if yara_match:
            print(f"[!] SUSPICIOUS (YARA_MATCH): {filename} -> {yara_match}")
            self.log_scan_result(filename, target_path, file_hash, "YARA_MATCH", yara_match)
            self.stats['yara_match'] += 1
            return

        # 4. Clean File
        print(f"[+] CLEAN: {filename}")
        self.log_scan_result(filename, target_path, file_hash, "CLEAN", "None")
        self.stats['clean'] += 1

    def scan_directory(self, directory_path):
        """Đệ quy quét toàn bộ thư mục"""
        print(f"\n--- BẮT ĐẦU QUÉT THƯ MỤC: {directory_path} ---")
        start_time = datetime.now()

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                filepath = os.path.join(root, file)
                self.scan_target(filepath)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        self.print_summary(duration)

    def print_summary(self, duration):
        """In báo cáo tổng kết ra terminal"""
        print("\n" + "="*40)
        print("          BÁO CÁO KẾT QUẢ QUÉT          ")
        print("="*40)
        print(f"Tổng số file đã quét: {self.stats['scanned']}")
        print(f"Phát hiện qua Database Hash: {self.stats['hash_match']}")
        print(f"Phát hiện qua YARA Rules:    {self.stats['yara_match']}")
        print(f"File an toàn:                {self.stats['clean']}")
        print(f"File lỗi không thể đọc:      {self.stats['errors']}")
        print(f"Thời gian quét:              {duration:.2f} giây")
        print("="*40)

    def close(self):
        """Đóng kết nối DB khi kết thúc chương trình"""
        if self.db_conn:
            self.db_conn.close()

if __name__ == "__main__":
    # Khởi tạo Scanner
    scanner = MalwareScanner(rules_path='rules/index.yar')
    
    while True:
        print("\n--- HỆ THỐNG PHÁT HIỆN MÃ ĐỘc ---")
        target = input("Nhập đường dẫn file hoặc thư mục cần quét (nhập 'q' để thoát): ").strip()
        
        # Bỏ dấu ngoặc kép nếu người dùng Copy as Path trên Windows
        target = target.strip('"\'') 
        
        if target.lower() == 'q':
            break
            
        if os.path.isfile(target):
            print(f"\n--- ĐANG QUÉT FILE: {target} ---")
            start = datetime.now()
            scanner.scan_target(target)
            dur = (datetime.now() - start).total_seconds()
            scanner.print_summary(dur)
        elif os.path.isdir(target):
            scanner.scan_directory(target)
        else:
            print("Đường dẫn không hợp lệ. Vui lòng thử lại.")
            
    scanner.close()
    print("Đã thoát chương trình.")