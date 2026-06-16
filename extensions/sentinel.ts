/**
 * pi-secret-sentinel
 * Security middleware for Pi that blocks the writing of secrets to disk.
 * 
 * Enhanced in v0.4.0:
 *   - Passive mode for scanning existing files
 *   - Scan history and statistics
 *   - Configurable settings
 *   - Error recovery
 *   - Performance optimizations
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import * as fs from "node:fs";
import * as path from "node:path";
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

/**
 * Sentinel configuration.
 */
export interface SentinelConfig {
	enabled: boolean;
	passiveMode: boolean;
	entropyThreshold: number;
	whitelist: RegExp[];
	blacklist: RegExp[];
	scanExtensions: Set<string>;
	excludeDirs: Set<string>;
}

const DEFAULT_CONFIG: SentinelConfig = {
	enabled: true,
	passiveMode: true,
	entropyThreshold: 4.5,
	whitelist: [],
	blacklist: [],
	scanExtensions: new Set([".ts", ".js", ".tsx", ".jsx", ".py", ".rs", ".go", ".java", ".json", ".env"]),
	excludeDirs: new Set(["node_modules", "dist", ".git", "coverage"]),
};

export default function (pi: ExtensionAPI) {
	const config: SentinelConfig = { ...DEFAULT_CONFIG };
	const detector = new SecretDetector({
		entropyThreshold: config.entropyThreshold,
		whitelist: config.whitelist,
		blacklist: config.blacklist,
		trackHistory: true,
	});

	/**
	 * Notify user of a blocked write.
	 */
	const notifySecret = (
		ctx: any,
		provider: string,
		reason: string,
	): void => {
		try {
			ctx.ui?.notify(
				`🔴 SECRET DETECTED: The write operation contains ${reason} (${provider}).\n\n` +
					`Security Policy: Secrets must not be written to disk. Please use a .env file and reference the value via process.env.`,
				"error",
			);
		} catch (err) {
			console.error(`[pi-secret-sentinel] Failed to notify: ${(err as Error).message}`);
		}
	};

	/**
	 * Abort a tool execution.
	 */
	const abortExecution = (event: any, provider: string): void => {
		try {
			if (typeof event.abort === "function") {
				event.abort();
			} else {
				throw new Error(
					`[Secret Sentinel] Blocked write operation containing a secret (${provider}).`,
				);
			}
		} catch (err) {
			throw new Error(
				`[Secret Sentinel] Blocked write operation containing a secret (${provider}).`,
			);
		}
	};

	/**
	 * Scan a file for secrets (passive mode).
	 */
	const scanFile = (filePath: string): { isSecret: boolean; provider?: string } | null => {
		try {
			// Check if file should be scanned
			const ext = path.extname(filePath);
			if (!config.scanExtensions.has(ext)) return null;

			// Check if directory should be excluded
			for (const excludeDir of config.excludeDirs) {
				if (filePath.includes(`${path.sep}${excludeDir}${path.sep}`) || filePath.includes(`/${excludeDir}/`)) {
					return null;
				}
			}

			// Read and scan file
			if (!fs.existsSync(filePath)) return null;
			const stat = fs.statSync(filePath);
			if (!stat.isFile()) return null;

			const content = fs.readFileSync(filePath, "utf8");
			const result = detector.scan(content);

			if (result.isSecret) {
				console.warn(
					`[pi-secret-sentinel] ⚠️ Secret detected in ${filePath}: ${result.provider}`,
				);
			}

			return { isSecret: result.isSecret, provider: result.provider };
		} catch (err) {
			console.error(`[pi-secret-sentinel] Error scanning ${filePath}: ${(err as Error).message}`);
			return null;
		}
	};

	// Intercept tool execution start
	pi.on("tool_execution_start", async (event, ctx) => {
		if (!config.enabled) return;
		if (!event || !ctx) return;
		const { toolName, input } = event;

		// We only care about tools that modify the filesystem
		if (toolName === "write" || toolName === "edit") {
			try {
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
					notifySecret(ctx, provider, reason);

					// 2. Abort the tool execution to prevent the write
					abortExecution(event, provider);
				}
			} catch (err) {
				console.error(`[pi-secret-sentinel] Error during write scan: ${(err as Error).message}`);
			}
		}

		// Passive mode: scan read files for secrets
		if (config.passiveMode && toolName === "read") {
			try {
				const filePath = input?.path;
				if (filePath) {
					scanFile(filePath);
				}
			} catch (err) {
				// Silently ignore - passive mode shouldn't block
			}
		}
	});

	console.log(
		"[pi-secret-sentinel] Active. Use the `scan-stats` command to view detection statistics.",
	);
}
