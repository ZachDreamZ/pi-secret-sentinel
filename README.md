# pi-secret-sentinel 🛡️

A security middleware extension for [Pi](https://pi.dev/) that intercepts and blocks the writing of sensitive credentials to your codebase.

[![Pi Package](https://img.shields.io/badge/Pi-Package-blue)](https://pi.dev/packages)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![npm version](https://img.shields.io/npm/v/pi-secret-sentinel.svg)](https://www.npmjs.com/package/pi-secret-sentinel)

## Features

- **Real-time Interception**: Blocks `write` and `edit` tool calls before they hit the disk.
- **Dual-Layer Detection**: Combines high-confidence regex patterns with Shannon Entropy analysis.
- **Broad Provider Support**: Detects keys for GitHub, OpenAI, AWS, Google Cloud, and more.
- **Intelligent Filtering**: Automatically ignores UUIDs, local paths, and common placeholders.
- **Zero-Configuration**: Works out of the box with no setup required.
- **Compatible** with any Pi-supported model and extension.

## Installation

```bash
pi install npm:pi-secret-sentinel
```

## Quick Start

After installation, the sentinel activates automatically. It monitors every filesystem modification.

### Example Blocked Operation

If the agent attempts to write a secret:
```typescript
// Agent tries to write this:
const apiKey = "SENSITIVE_SECRET_TOKEN_EXAMPLE_1234567890";
```

The sentinel will immediately abort the execution and notify you:

> 🔴 **SECRET DETECTED**: The write operation contains a known secret pattern (OpenAI API Key).
> 
> **Security Policy**: Secrets must not be written to disk. Please use a `.env` file and reference the value via `process.env`.

## How It Works

The sentinel operates as a middleware layer using the `tool_execution_start` event:

### 1. Pattern Matching (Deterministic)
Matches strings against a library of high-confidence regular expressions for known service tokens (e.g., `ghp_` for GitHub, `sk-` for OpenAI).

### 2. Entropy Analysis (Probabilistic)
Calculates the **Shannon Entropy** of isolated tokens. Strings that exhibit high randomness (entropy $> 4.5$) and exceed a minimum length are flagged as potential secrets, catching custom tokens that don't follow a known pattern.

### 3. False Positive Mitigation
To prevent disruption, the sentinel filters out:
- **UUIDs**: `550e8400-e29b-41d4-a716-446655440000`
- **Paths**: `/home/user/project` or `C:\Users\Vendex\...`
- **Placeholders**: `YOUR_API_KEY_HERE`

## Compatibility

- ✅ Works with all Pi-supported LLMs
- ✅ Zero performance overhead
- ✅ Safe for use in production repositories
- ✅ No conflicts with other Pi extensions

## Troubleshooting

### False Positive
If a legitimate string is being blocked, ensure it doesn't accidentally match a known secret pattern or exhibit extremely high randomness (like a long, random base64 hash).

### Not Blocking
Ensure the extension is installed and active. Check `pi list` to verify installation.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request to add new secret patterns or improve entropy thresholds.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-pattern`)
3. Commit your changes (`git commit -m 'feat: add X provider pattern'`)
4. Push to the branch (`git push origin feature/new-pattern`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Pi](https://pi.dev/) - The AI coding agent
