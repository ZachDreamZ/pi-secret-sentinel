# Technical Specification: pi-secret-sentinel

## 1. Architecture Overview
`pi-secret-sentinel` is a Pi extension that hooks into the tool execution lifecycle. It analyzes the `input` of filesystem-modifying tools before they are executed by the Pi runtime.

## 2. Detection Logic

### A. Pattern-Based Detection (RegEx)
The sentinel uses a curated list of regex patterns. If any pattern matches, the content is immediately flagged.
**Key Patterns**:
- **GitHub**: `ghp_[a-zA-Z0-9]{36}`
- **OpenAI**: `sk-[a-zA-Z0-9]{48}`
- **Generic API Key**: `(?i)(api_key|secret|token|password)[\s:=]+[a-zA-Z0-9_\-]{16,}`
- **AWS Access Key**: `AKIA[0-9A-Z]{16}`

### B. Entropy-Based Detection
For strings that don't match a known pattern but look "random," the sentinel calculates Shannon Entropy:
$$H = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
**Thresholds**:
- **String Length**: Only analyze strings $> 12$ characters.
- **Entropy Score**: Strings with entropy $> 4.5$ and high character diversity are flagged as potential secrets.

### C. False Positive Mitigation
Strings are ignored if they match:
- UUID format: `[0-9a-f]{8}-[0-9a-f]{4}-...`
- Local file paths: Starting with `/`, `./`, or `C:\`.
- Common placeholders: `YOUR_API_KEY`, `REPLACE_ME`.

## 3. Implementation Design

### A. `SecretDetector` (Class)
- `scan(text: string): DetectionResult`: Returns whether a secret was found and the reason (Pattern vs Entropy).
- `calculateEntropy(text: string): number`: Internal math helper.
- `isFalsePositive(text: string): boolean`: Filters out UUIDs and paths.

### B. `SentinelInterceptor` (Class)
- `handleToolStart(event: ToolExecutionStartEvent)`: 
    - Checks if `event.toolName` is `write` or `edit`.
    - Extracts content from `event.input`.
    - Calls `SecretDetector.scan()`.
    - If secret found $\to$ `event.abort()` (or equivalent runtime block) and `ctx.ui.notify`.

## 4. Lifecycle Integration
The extension registers for the `tool_execution_start` event:
```typescript
pi.on("tool_execution_start", async (event, ctx) => {
    if (isFileSystemTool(event.toolName)) {
        const result = detector.scan(event.input);
        if (result.isSecret) {
            ctx.ui.notify("🔴 SECRET DETECTED", "error");
            event.abort(); 
        }
    }
});
```

## 5. Performance & Complexity
- **Time Complexity**: $O(T \cdot P)$ where $T$ is text length and $P$ is number of patterns. Since $P$ is small ($< 50$), this is effectively $O(T)$.
- **Space Complexity**: $O(1)$ beyond the input buffer.
