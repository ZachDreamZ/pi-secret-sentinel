# Proposal: pi-secret-sentinel

## 1. Problem Statement
AI agents often inadvertently write sensitive information—such as API keys, private tokens, and passwords—directly into source code or configuration files. Once committed to a repository, these secrets are compromised, even if deleted in later commits. 

There is currently no "safety net" in the Pi toolchain that prevents the `write` or `edit` tools from committing secrets to the filesystem.

## 2. Goal
Create a Pi extension that acts as a **security middleware**. It will intercept all filesystem-modifying tool calls and block any operation that attempts to write a detected secret to disk, forcing the agent to use secure alternatives like environment variables.

## 3. Core Features
### A. Real-time Interception
- Subscribe to the `tool_execution_start` event.
- Monitor all `write` and `edit` tool calls.
- Block execution immediately if a secret is detected in the payload.

### B. Dual-Layer Detection
- **Pattern-Based**: Use high-confidence regexes for common providers (GitHub, OpenAI, AWS, Google, etc.).
- **Entropy-Based**: Calculate Shannon Entropy for arbitrary strings to catch unique or custom secrets that don't follow a known pattern.

### C. Intelligent Filtering
- **Ignore List**: Prevent false positives by ignoring known safe patterns (e.g., UUIDs, local paths, common placeholder strings like `YOUR_API_KEY`).
- **Context Awareness**: Distinguish between a secret being *read* (allowed) and a secret being *written* (blocked).

### D. Agent Feedback Loop
- Trigger a high-visibility `ctx.ui.notify` alert.
- Provide a clear directive to the agent: *"Secret detected in write operation. Please move this value to a .env file and reference it via process.env."*

## 4. Success Criteria
- **Zero Leakage**: No known common API key patterns are allowed to be written to disk.
- **Low False Positives**: Standard code, paths, and UUIDs are not flagged as secrets.
- **Zero Latency**: The check must be near-instantaneous to avoid degrading the agent's performance.
- **Hard Stop**: The tool execution is successfully aborted before the filesystem is touched.

## 5. Non-Goals
- This is not a secret *manager* (it doesn't store keys).
- This is not a *scanner* for existing files (it only monitors new writes/edits).
- It will not automatically "fix" the code; it only blocks the dangerous action.
