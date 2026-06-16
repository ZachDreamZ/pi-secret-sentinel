# Changelog

## [0.4.0] - 2026-06-16

### Major Security Enhancement Release

#### New Features

- **Passive Mode**: Automatically scans files during `read` operations to detect existing leaks.
- **Expanded Pattern Library**: Support for 25+ secret types including Stripe, Discord, MongoDB, and more.
- **Configurable Detector**: Added `DetectorConfig` to adjust entropy thresholds and token lengths.
- **Whitelist/Blacklist Support**: Allows suppressing false positives or forcing detections.
- **Scan History & Stats**: Tracks detections, durations, and overall security metrics.
- **Error Recovery**: Added try-catch guards to prevent extension crashes during scanning.

#### Improvements

- **Enhanced False Positive Mitigation**: Added support for dates, IP addresses, and various hash types.
- **Tokenization Optimization**: Improved splitting logic for higher precision.
- **Scan Performance**: Optimized regex execution and entropy calculations.

#### Test Coverage

- Expanded unit tests for new patterns and config options.
- Added performance benchmarks for scan speed.

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
