"use strict";
/**
 * pi-secret-sentinel
 * Security middleware for Pi that blocks the writing of secrets to disk.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = default_1;
const detector_1 = require("./detector");
function default_1(pi) {
    const detector = new detector_1.SecretDetector();
    // Intercept tool execution start
    pi.on("tool_execution_start", async (event, ctx) => {
        const { toolName, input } = event;
        // We only care about tools that modify the filesystem
        if (toolName === "write" || toolName === "edit") {
            // Secrets can be in the 'content' field (for write) or 'oldText/newText' (for edit)
            const contentToScan = JSON.stringify(input);
            const result = detector.scan(contentToScan);
            if (result.isSecret) {
                const provider = result.provider || "unknown";
                const reason = result.reason === "pattern"
                    ? "a known secret pattern"
                    : "high-entropy random characters";
                // 1. Notify the agent and user with a high-priority error
                ctx.ui.notify(`🔴 SECRET DETECTED: The write operation contains ${reason} (${provider}).\n\n` +
                    `Security Policy: Secrets must not be written to disk. Please use a .env file and reference the value via process.env.`, "error");
                // 2. Abort the tool execution to prevent the write
                // In Pi's Extension API, calling event.abort() prevents the tool from running.
                if (typeof event.abort === "function") {
                    event.abort();
                }
                else {
                    // Fallback for different Pi versions: throwing an error usually blocks execution
                    throw new Error(`[Secret Sentinel] Blocked write operation containing a secret (${provider}).`);
                }
            }
        }
    });
}
