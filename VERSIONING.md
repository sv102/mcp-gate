# Versioning & Changelog Policy

## Version Format

**Public:** `MAJOR.MINOR.PATCH` (e.g. `0.1.0`, `0.1.1`, `0.2.0`)
**Internal:** `MAJOR.MINOR.PATCH.DEV` (e.g. `0.1.0.1`, `0.1.0.2`) — developer only

### Levels

| Level | When to increment | Example |
|-------|-------------------|---------|
| **MAJOR** | Breaking changes — users must update configs/integrations | `1.0.0` |
| **MINOR** | New features, backward-compatible | `0.2.0` |
| **PATCH** | Bug fixes, small improvements, security patches | `0.1.1` |
| **DEV** | Internal iteration between public releases | `0.1.1.3` |

### Rules

1. DEV counter resets to 0 on every PATCH/MINOR/MAJOR bump
2. DEV versions are **never** visible to users (not in health endpoint, not in UI, not in CHANGELOG.md)
3. PATCH increments conservatively — accumulate several DEV iterations before publishing
4. MINOR bumps for significant new features or UI sections
5. Stay on `0.x.y` until API is stable for third-party integrations → then `1.0.0`

## Files

| File | In Git | Audience | Content |
|------|--------|----------|---------|
| `CHANGELOG.md` | ✅ | Public | Only `MAJOR.MINOR.PATCH` entries, keepachangelog.com format |
| `DEVLOG.md` | ❌ (.gitignore) | Developer | All `MAJOR.MINOR.PATCH.DEV` entries, chronological |
| `app/constants.py` | ✅ | Code | `VERSION` (public) + `DEV_BUILD` (internal counter) |

## Workflow

### During development

```
1. Make changes
2. Increment DEV_BUILD in constants.py
3. Add entry to DEVLOG.md
4. Commit (message: "dev: description")
```

### Publishing a release

```
1. Decide next version (PATCH / MINOR / MAJOR)
2. Set VERSION = new version, DEV_BUILD = 0 in constants.py
3. Consolidate DEVLOG entries → write CHANGELOG.md entry
4. Commit: "release: v0.1.1"
5. Tag: git tag -s v0.1.1 -m "v0.1.1"
6. Push: git push && git push --tags
7. Create GitHub Release from tag (copy CHANGELOG entry)
```

### CHANGELOG.md format (keepachangelog.com)

```markdown
## X.Y.Z — YYYY-MM-DD

### Added
- New feature description

### Changed
- Modified behavior

### Fixed
- Bug fix description

### Security
- Security improvement

### Removed
- Removed feature

### Deprecated
- Feature marked for removal
```

### DEVLOG.md format

```markdown
## 0.1.0.3 — 2026-03-30

- Fixed WebSocket reconnect on auth timeout
- Adjusted rate limit error message

## 0.1.0.2 — 2026-03-29

- Added param validation for command sets
```

## Git Tags

- Only public versions get tags: `v0.1.0`, `v0.1.1`
- Tags are GPG-signed: `git tag -s v0.1.1 -m "v0.1.1"`
- No tags for DEV versions
- GitHub Releases created only for public versions

## Health Endpoint

```json
{"version": "0.1.0"}
```

Always shows `VERSION` only. `DEV_BUILD` is never exposed via API.
