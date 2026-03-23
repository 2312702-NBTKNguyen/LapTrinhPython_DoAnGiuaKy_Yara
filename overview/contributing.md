# Hướng dẫn đóng góp - YARA Malware Scanner

## Quy tắc coding

### Code style

1. **Docstrings:** Sử dụng Google style docstrings
```python
def function(arg1: str, arg2: int) -> bool:
    """Short description.
    
    Longer description if needed.
    
    Args:
        arg1: Description of arg1.
        arg2: Description of arg2.
    
    Returns:
        Description of return value.
    
    Raises:
        ValueError: If arg2 is negative.
    """
```

2. **Type hints:** Bắt buộc cho tất cả public APIs
```python
def scan_file(filepath: str, rules: yara.Rules) -> list[Match]:
    ...
```

3. **Comments:** Section-level, không comment từng dòng
```python
# GOOD: Section comment
# Calculate file hashes for database lookup
hashes = calculate_file_hashes(filepath)

# BAD: Line-by-line comment
hashes = calculate_file_hashes(filepath)  # Calculate hashes
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

### Error handling

1. **Sử dụng custom exceptions** từ `exceptions.py`
2. **Catch specific exceptions**, không catch generic `Exception`
3. **Log lỗi** với context đầy đủ
4. **Không swallow errors** (catch rồi bỏ qua)

```python
# GOOD
try:
    result = db.query(sql, params)
except DatabaseError as e:
    logger.error(f"Query failed: {e}", exc_info=True)
    raise

# BAD
try:
    result = db.query(sql, params)
except:
    pass
```

### File organization

1. **Mỗi file** có header comment mô tả purpose
2. **Group related functions** vào cùng class/module
3. **Keep files focused** - 1 file = 1 responsibility
4. **Max file length:** ~300 lines

### Header template

```python
"""
Module name - Short description.

Longer description of what this module does,
its main classes, and key responsibilities.

Example:
    Basic usage example if helpful.

Attributes:
    MODULE_CONSTANT: Description.
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

### Test structure

```python
def test_zip_scanning():
    """Test ZIP archive scanning."""
    scanner = ArchiveScanner(rules)
    
    # Test với fake malware
    with tempfile.NamedTemporaryFile(suffix='.zip') as f:
        create_test_zip(f.name, ['test_malware.txt'])
        results = scanner.scan_zip(f.name)
        
    assert len(results) == 1
    assert results[0].rule == 'TestRule'
```

## Git workflow

### Branch naming
- `feature/archive-scanning`
- `fix/database-connection`
- `docs/README-update`

### Commit messages
```
feat: Add ZIP archive scanning support
fix: Handle password-protected ZIPs
docs: Add feature specifications
test: Add archive scanning tests
```

### Pull request checklist
- [ ] Code follows style guide
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No hardcoded secrets
- [ ] Error handling implemented

## Directory structure rules

```
1. malware_scanner/     - Core business logic
2. rules/               - YARA rules only
3. tests/               - All test files
4. overview/            - Documentation only
5. database/            - SQL scripts
6. src/                 - Data pipeline scripts
```

## Dependencies

### Adding new dependencies

1. **Check if stdlib can do it** first
2. **Evaluate alternatives** (popularity, maintenance)
3. **Pin versions** in requirements.txt
4. **Document** why it's needed

```
# requirements.txt
# Archive scanning
py7zr>=0.20.0      # 7z support
rarfile>=4.0        # RAR support
```

## Review process

### Code review checklist
- [ ] Follows code style
- [ ] Error handling complete
- [ ] Tests included
- [ ] Documentation updated
- [ ] No security issues
- [ ] Performance considered
