# Hướng dẫn đóng góp - YARA Malware Scanner

## Quy tắc coding

### Code style

1. **Docstrings:** Sử dụng Google style docstrings

```python
def function(arg1: str, arg2: int) -> bool:
    """Mô tả ngắn gọn.

    Mô tả chi tiết hơn nếu cần.

    Args:
        arg1: Mô tả arg1.
        arg2: Mô tả arg2.

    Returns:
        Mô tả giá trị trả về.

    Raises:
        ValueError: Nếu arg2 âm.
    """
```

2. **Type hints:** Bắt buộc cho tất cả public APIs

```python
def scan_file(filepath: str, rules: yara.Rules) -> list[Match]:
    ...
```

3. **Comments:** Section-level, không comment từng dòng

```python
# TỐT: Section comment
# Tính file hashes để tra cứu database
hashes = calculate_file_hashes(filepath)

# KHÔNG TỐT: Line-by-line comment
hashes = calculate_file_hashes(filepath)  # Tính hashes
```

4. **Imports:** Sắp xếp theo thứ tự

```python
# Standard library
import os
from datetime import datetime

# Third-party
import yara
import psycopg2

# Local
from .engine import scan_with_yara
from .db import check_hash_in_db
```

### Xử lý lỗi

1. **Sử dụng custom exceptions** từ `exceptions.py`
2. **Catch specific exceptions**, không catch generic `Exception`
3. **Ghi log lỗi** với context đầy đủ
4. **Không swallow errors** (catch rồi bỏ qua)

```python
# TỐT
try:
    result = db.query(sql, params)
except DatabaseError as e:
    logger.error(f"Truy vấn thất bại: {e}", exc_info=True)
    raise

# KHÔNG TỐT
try:
    result = db.query(sql, params)
except:
    pass
```

### Tổ chức file

1. **Mỗi file** có header comment mô tả mục đích
2. **Group related functions** vào cùng class/module
3. **Keep files focused** - 1 file = 1 trách nhiệm
4. **Max file length:** ~300 lines

### Header template

```python
"""
Tên module - Mô tả ngắn gọn.

Mô tả chi tiết hơn về module này,
các class chính, và trách nhiệm chính.

Example:
    Ví dụ sử dụng nếu hữu ích.

Attributes:
    MODULE_CONSTANT: Mô tả.
"""
```

## Testing

### Fake malware samples

Tạo test samples với YARA pattern strings:

```python
# samples/test_emotet.txt
MZ - Script Auto Update (Fake)
WshShell.Run "powershell -w hidden -enc ..."
Net.WebClient
http://example.com/wp-content/payload.exe
```

### Cấu trúc test

```python
def test_zip_scanning():
    """Test quét ZIP archive."""
    scanner = ArchiveScanner(rules)

    # Test với fake malware
    with tempfile.NamedTemporaryFile(suffix='.zip') as f:
        create_test_zip(f.name, ['test_malware.txt'])
        results = scanner.scan_zip(f.name)

    assert len(results) == 1
    assert results[0].rule == 'TestRule'
```

## Git workflow

### Đặt tên branch

- `feature/archive-scanning`
- `fix/database-connection`
- `docs/README-update`

### Commit messages

```
feat: Thêm hỗ trợ quét ZIP archive
fix: Xử lý ZIP được bảo vệ bằng password
docs: Thêm đặc tả tính năng
test: Thêm test quét archive
```

### Pull request checklist

- [ ] Code tuân thủ style guide
- [ ] Tests pass
- [ ] Documentation được cập nhật
- [ ] Không có hardcoded secrets
- [ ] Xử lý lỗi đầy đủ

## Quy tắc cấu trúc thư mục

```
1. malware_scanner/     - Core business logic
2. rules/               - YARA rules only
3. tests/               - Tất cả file test
4. overview/            - Documentation only
5. database/            - SQL scripts
6. scripts/             - Data pipeline scripts
```

## Dependencies

### Thêm dependencies mới

1. **Kiểm tra xem stdlib có thể làm được không** trước
2. **Đánh giá alternatives** (popularity, maintenance)
3. **Pin versions** trong requirements.txt
4. **Document** lý do cần

```
# requirements.txt
# Quét archive
py7zr>=0.20.0      # Hỗ trợ 7z
rarfile>=4.0        # Hỗ trợ RAR
```

## Review process

### Code review checklist

- [ ] Tuân thủ code style
- [ ] Xử lý lỗi đầy đủ
- [ ] Tests included
- [ ] Documentation cập nhật
- [ ] Không có vấn đề bảo mật
- [ ] Hiệu suất được xem xét
