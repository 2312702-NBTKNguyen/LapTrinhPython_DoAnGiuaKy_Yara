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
- [x] Archive scanning (ZIP, 7z)
- [x] Core YARA rules
- [x] Custom exception hierarchy
- [x] Project documentation
- [x] JSON/CSV export
- [x] uv support

## Version 2.0 - Enhanced Features (Future)

### Phase 1: YARA Rules Enhancement
- [ ] Packer detection rules
- [ ] Crypto library detection
- [ ] Suspicious API patterns
- [ ] Anti-analysis techniques
- [ ] Network indicator rules

### Phase 2: Additional Features
- [ ] RAR file support (requires unrar)
- [ ] Scan scheduling
- [ ] Memory scanning (requires root)

## Priority matrix

| Feature | User Value | Technical Effort | Priority |
|---------|------------|------------------|----------|
| Archive scanning | High | Medium | ✅ Done |
| Core YARA rules | Medium | Low | ✅ Done |
| Error handling | Medium | Low | ✅ Done |
| Memory scanning | Medium | High | P2 |
| REST API | Low | Medium | P3 |
