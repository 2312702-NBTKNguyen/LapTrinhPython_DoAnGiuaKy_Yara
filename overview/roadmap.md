# Roadmap - YARA Malware Scanner

## Current Version (v1.0)

### Completed features
- [x] Hash-based detection (SHA256)
- [x] YARA rule scanning
- [x] PostgreSQL integration
- [x] MalwareBazaar API integration
- [x] CLI interface
- [x] Terminal reporting
- [x] 14 malware family rules

## Version 2.0 - Enhanced Scanning

### Phase 1: Archive Scanning (Week 1-2)
- [ ] ZIP file support (stdlib zipfile)
- [ ] 7z file support (py7zr)
- [ ] RAR file support (rarfile)
- [ ] Nested archive handling
- [ ] Archive bomb protection
- [ ] In-memory extraction (no disk writes)

### Phase 2: YARA Rules Enhancement (Week 2-3)
- [ ] Generic PE analyzer rule
- [ ] Packer detection rules
- [ ] Crypto library detection
- [ ] Suspicious API patterns
- [ ] Anti-analysis techniques
- [ ] Network indicator rules

### Phase 3: Error Handling & Code Quality (Week 3)
- [ ] Custom exception hierarchy
- [ ] Comprehensive logging
- [ ] Input validation
- [ ] Type hints throughout
- [ ] Docstrings for all public APIs

## Version 3.0 - TUI Interface

### Phase 4: TUI Foundation (Week 4-5)
- [ ] Textual framework setup
- [ ] Main application structure
- [ ] Screen navigation system
- [ ] CSS theme design

### Phase 5: TUI Features (Week 5-6)
- [ ] File/directory browser
- [ ] Scan progress display
- [ ] Results table with sorting
- [ ] YARA rules viewer
- [ ] Scan history browser
- [ ] Keyboard shortcuts

## Version 4.0 - Advanced Features (Future)

### Phase 6: Memory Scanning
- [ ] Process enumeration
- [ ] Memory region scanning
- [ ] Injected code detection
- [ ] Root permission handling

### Phase 7: Additional Features
- [ ] JSON/CSV export
- [ ] Scan scheduling
- [ ] Email notifications
- [ ] REST API

## Timeline

| Version | Features | Duration | Status |
|---------|----------|----------|--------|
| v1.0 | Core scanning | Done | ✅ Released |
| v2.0 | Archive + Rules | 3 weeks | 🔄 In Progress |
| v3.0 | TUI Interface | 3 weeks | ⏳ Planned |
| v4.0 | Memory + Extras | TBD | 📋 Backlog |

## Priority matrix

| Feature | User Value | Technical Effort | Priority |
|---------|------------|------------------|----------|
| Archive scanning | High | Medium | P0 |
| TUI interface | High | High | P0 |
| Core YARA rules | Medium | Low | P1 |
| Error handling | Medium | Low | P1 |
| Memory scanning | Medium | High | P2 |
| REST API | Low | Medium | P3 |
