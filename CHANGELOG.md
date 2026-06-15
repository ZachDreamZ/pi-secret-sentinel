# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-14

### Added
- **Comprehensive Test Suite**: Added Jest tests for pattern detection, entropy analysis, and false positive mitigation.

### Fixed
- **Critical: Tokenization Bug**: Fixed the splitting regex `/[ \s,;="']+ /` $\to$ `/[ \s,;="']+/` to correctly isolate secrets in `key="value"` assignments.
- **Critical: Build failure**: Fixed `tsconfig.json` rootDir and include paths.
- **High: Null Safety**: Added guards to `sentinel.ts` for `event`, `ctx`, and `input`.
- **Medium: JSON Key Scanning**: Implemented recursive value scanner to avoid false positives on JSON keys.
- **Medium: False Positive Tuning**: Added SHA-256 hash detection to avoid flagging hashes as secrets.
- **Low: Pattern updates**: Added `github_pat_` and other newer token formats.
- **Low: Entropy threshold**: Adjusted minimum token length to 10 for better detection.

## [0.2.1] - 2026-06-14
Initial release.
