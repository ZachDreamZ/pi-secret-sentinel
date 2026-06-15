/**
 * pi-secret-sentinel
 * Security middleware for Pi that blocks the writing of secrets to disk.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { SecretDetector } from "./detector";

/**
 * Recursively extracts all string values from an object to avoid scanning keys.
 */
function extractValues(obj: any, values: string[] = []) {
	if (typeof obj === "string") {
		values.push(obj);
	} else if (Array.isArray(obj)) {
		for (const item of obj) {
			extractValues(item, values);
		}
	} else if (obj !== null && typeof obj === "object") {
		for (const key in obj) {
			// Target common Pi tool fields specifically
			if (
				key === "content" ||
				key === "newText" ||
				key === "oldText" ||
				key === "text"
			) {
				extractValues(obj[key], values);
			} else {
				extractValues(obj[key], values);
			}
		}
	}
	return values;
}

export default function (pi: ExtensionAPI) {
	const detector = new SecretDetector();

	// Intercept tool execution start
	pi.on("tool_execution_start", async (event, ctx) => {
		if (!event || !ctx) return;
		const { toolName, input } = event;

		// We only care about tools that modify the filesystem
		if (toolName === "write" || toolName === "edit") {
			const values = extractValues(input);
			const contentToScan = values.join(" ");

			const result = detector.scan(contentToScan);

			if (result.isSecret) {
				const provider = result.provider || "unknown";
				const reason =
					result.reason === "pattern"
						? "a known secret pattern"
						: "high-entropy random characters";

				// 1. Notify the agent and user with a high-priority error
				ctx.ui?.notify(
					`🔴 SECRET DETECTED: The write operation contains ${reason} (${provider}).\n\n` +
						`Security Policy: Secrets must not be written to disk. Please use a .env file and reference the value via process.env.`,
					"error",
				);

				// 2. Abort the tool execution to prevent the write
				// In Pi's Extension API, calling event.abort() prevents the tool from running.
				if (typeof event.abort === "function") {
					event.abort();
				} else {
					// Fallback for different Pi versions: throwing an error usually blocks execution
					throw new Error(
						`[Secret Sentinel] Blocked write operation containing a secret (${provider}).`,
					);
				}
			}
		}
	});
}
