# Implementation Tasks: pi-secret-sentinel

## Phase 1: Foundation
- [ ] Initialize `package.json` and TypeScript config.
- [ ] Create project folder structure (`src/`, `docs/`).

## Phase 2: Core Detection Logic (`SecretDetector`)
- [ ] Implement the regex pattern library for common API keys.
- [ ] Implement the Shannon Entropy calculation function.
- [ ] Implement the false-positive filter (UUIDs, paths).
- [ ] Create unit tests for various secret strings and safe strings.

## Phase 3: Interception Layer (`SentinelInterceptor`)
- [ ] Implement the `tool_execution_start` event handler.
- [ ] Logic to isolate `write` and `edit` tool inputs.
- [ ] Integrate `SecretDetector` into the handler.
- [ ] Implement the `ctx.ui.notify` alert system.

## Phase 4: Pi Integration
- [ ] Register the extension and ensure it loads on startup.
- [ ] Verify that `event.abort()` effectively stops the tool execution.
- [ ] Ensure zero performance lag during normal writes.

## Phase 5: Adversarial QA
- [ ] Test with a variety of real-looking API keys.
- [ ] Test with "edge case" safe strings (long random hashes that aren't secrets).
- [ ] Run Pi Lens diagnostics to ensure zero blockers.

## Phase 6: Release
- [ ] Update README.md with security warnings and usage.
- [ ] Publish to npm using `publish-pi-package` skill.
- [ ] Final GitHub release.
