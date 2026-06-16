/**
 * SecretDetector
 * Logic for identifying API keys, tokens, and sensitive strings using
 * a combination of pattern matching and Shannon Entropy.
 *
 * Enhanced in v0.4.0:
 *   - Expanded pattern library (20+ secret types)
 *   - Configurable entropy threshold
 *   - Whitelist/blacklist support
 *   - Scan history tracking
 *   - Performance optimizations
 */

export interface DetectionResult {
	isSecret: boolean;
	reason: "pattern" | "entropy" | "none";
	provider?: string;
	confidence: number; // 0.0 to 1.0
}

export interface DetectorConfig {
	entropyThreshold: number;
	minTokenLength: number;
	enabledProviders: string[];
	whitelist: RegExp[];
	blacklist: RegExp[];
	trackHistory: boolean;
}

export interface ScanRecord {
	timestamp: number;
	text: string;
	result: DetectionResult;
	duration: number;
}

const DEFAULT_CONFIG: DetectorConfig = {
	entropyThreshold: 4.5,
	minTokenLength: 10,
	enabledProviders: [], // Empty means all enabled
	whitelist: [],
	blacklist: [],
	trackHistory: false,
};

export class SecretDetector {
	/**
	 * High-confidence patterns for known API key formats.
	 * Expanded from 6 to 25+ patterns covering major services.
	 */
	private readonly PATTERNS: Record<string, RegExp> = {
		// Version Control
		"GitHub Personal Access Token":
			/ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,}/,
		"GitHub OAuth Token": /gho_[a-zA-Z0-9]{36}/,
		"GitHub App Token": /(ghu|ghs)_[a-zA-Z0-9]{36}/,
		"GitLab Personal Access Token": /glpat-[a-zA-Z0-9_-]{20,}/,
		"Bitbucket App Password":
			/[a-zA-Z0-9]{2,}-[a-zA-Z0-9]{2,}-[a-zA-Z0-9]{20,}/,

		// Cloud Providers
		"AWS Access Key ID": /AKIA[0-9A-Z]{16}/,
		"AWS Secret Access Key":
			/aws_secret_access_key[\s:=]+['"]?([a-zA-Z0-9/+=]{40})['"]?/i,
		"AWS Session Token": /FwoGZXIvYXdz[a-zA-Z0-9+/=]{100,}/,
		"Google API Key": /AIza[0-9A-Za-z-_]{35}/,
		"Google OAuth Token": /ya29\.[a-zA-Z0-9_-]{100,}/,
		"Azure Tenant Secret": /az-tenant-[a-zA-Z0-9_~.-]{34}/,

		// AI/ML Services
		"OpenAI API Key": /sk-[a-zA-Z0-9]{48}/,
		"OpenAI Project Key": /sk-proj-[a-zA-Z0-9]{48,}/,
		"Anthropic API Key": /sk-ant-[a-zA-Z0-9-]{32,}/,
		"Hugging Face Token": /hf_[a-zA-Z0-9]{20,}/,
		"Replicate API Token": /r8_[a-zA-Z0-9]{40}/,

		// Communication
		"Slack Bot Token": /xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}/,
		"Slack User Token": /xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}/,
		"Slack Webhook URL":
			/https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/,
		"Discord Bot Token":
			/[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}/,
		"Discord Webhook URL":
			/https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/,

		// Payment
		"Stripe Secret Key": /sk_(?:live|test)_[a-zA-Z0-9]{24,}/,
		"Stripe Restricted Key": /rk_(?:live|test)_[a-zA-Z0-9]{24,}/,
		"PayPal Client Secret": /E[a-zA-Z0-9_-]{32,}/,

		// Databases
		"MongoDB Connection String": /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^/]+/,
		"PostgreSQL Connection String": /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/]+/,
		"MySQL Connection String": /mysql:\/\/[^:]+:[^@]+@[^/]+/,

		// Cryptocurrency
		"Bitcoin Private Key": /[5KL][1-9A-HJ-NP-Za-km-z]{50,51}/,
		"Ethereum Private Key": /0x[a-fA-F0-9]{64}/,

		// Generic Patterns
		"Generic Secret/Token":
			/\b(?:api_key|secret|token|password|auth_token|access_key)\b[\s:=]+['"]?([^\s,;="']{12,})['"]?/i,
		"JWT Token": /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/,
		"Private Key": /-----BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----/,
		"SSH Public Key": /ssh-(rsa|ed25519|dss) AAAA[0-9A-Za-z+/]+[=]{0,3}/,
	};

	/**
	 * Strings that look like secrets but are actually safe.
	 */
	private readonly FALSE_POSITIVE_PATTERNS = [
		/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i, // UUID
		/^(\/|[a-zA-Z]:\\).*$/, // Absolute paths
		/^\.\/.*$/, // Relative paths
		/YOUR_API_KEY|REPLACE_ME|EXAMPLE_TOKEN|PLACEHOLDER|xxx+|XXXX+/i, // Placeholders
		/\b[0-9a-f]{64}\b/i, // SHA-256 hashes
		/\b[0-9a-f]{40}\b/i, // SHA-1 hashes
		/\b[0-9a-f]{32}\b/i, // MD5 hashes
		/^\d{4}-\d{2}-\d{2}$/, // Date format
		/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, // IP address
	];

	private config: DetectorConfig;
	private history: ScanRecord[] = [];

	constructor(config?: Partial<DetectorConfig>) {
		this.config = { ...DEFAULT_CONFIG, ...config };
	}

	/**
	 * Update the detector configuration.
	 */
	public configure(config: Partial<DetectorConfig>): void {
		this.config = { ...this.config, ...config };
	}

	/**
	 * Get the current configuration.
	 */
	public getConfig(): DetectorConfig {
		return { ...this.config };
	}

	/**
	 * Get scan history.
	 */
	public getHistory(): ScanRecord[] {
		return [...this.history];
	}

	/**
	 * Clear scan history.
	 */
	public clearHistory(): void {
		this.history = [];
	}

	/**
	 * Scans text for potential secrets.
	 */
	public scan(text: string): DetectionResult {
		const startTime = performance.now();

		if (!text || typeof text !== "string") {
			return { isSecret: false, reason: "none", confidence: 0 };
		}

		// Check blacklist first (always block)
		for (const pattern of this.config.blacklist) {
			if (pattern.test(text)) {
				const result: DetectionResult = {
					isSecret: true,
					reason: "pattern",
					provider: "Blacklisted Pattern",
					confidence: 1.0,
				};
				this.recordScan(text, result, startTime);
				return result;
			}
		}

		// Check whitelist (always allow)
		for (const pattern of this.config.whitelist) {
			if (pattern.test(text)) {
				const result: DetectionResult = {
					isSecret: false,
					reason: "none",
					confidence: 0,
				};
				this.recordScan(text, result, startTime);
				return result;
			}
		}

		// 1. Pattern Matching (Highest Confidence)
		for (const [provider, regex] of Object.entries(this.PATTERNS)) {
			// Skip if provider is disabled
			if (
				this.config.enabledProviders.length > 0 &&
				!this.config.enabledProviders.includes(provider)
			) {
				continue;
			}

			if (regex.test(text)) {
				const result: DetectionResult = {
					isSecret: true,
					reason: "pattern",
					provider,
					confidence: 1.0,
				};
				this.recordScan(text, result, startTime);
				return result;
			}
		}

		// 2. Entropy Analysis (Probabilistic)
		const tokens = text.split(/[\s,;="']+/);
		for (const token of tokens) {
			if (token.length < this.config.minTokenLength) continue;
			if (this.isFalsePositive(token)) continue;

			const entropy = this.calculateEntropy(token);
			if (entropy > this.config.entropyThreshold) {
				const result: DetectionResult = {
					isSecret: true,
					reason: "entropy",
					provider: "Unknown High-Entropy String",
					confidence: 0.7,
				};
				this.recordScan(text, result, startTime);
				return result;
			}
		}

		const result: DetectionResult = {
			isSecret: false,
			reason: "none",
			confidence: 0,
		};
		this.recordScan(text, result, startTime);
		return result;
	}

	/**
	 * Record a scan in history.
	 */
	private recordScan(
		text: string,
		result: DetectionResult,
		startTime: number,
	): void {
		if (!this.config.trackHistory) return;

		const duration = performance.now() - startTime;
		this.history.push({
			timestamp: Date.now(),
			text: text.substring(0, 200), // Truncate for storage
			result,
			duration,
		});

		// Keep history bounded
		if (this.history.length > 1000) {
			this.history.shift();
		}
	}

	/**
	 * Calculates Shannon Entropy of a string.
	 * H = -sum(p(x) * log2(p(x)))
	 */
	private calculateEntropy(text: string): number {
		const len = text.length;
		const frequencies: Record<string, number> = {};

		for (const char of text) {
			frequencies[char] = (frequencies[char] || 0) + 1;
		}

		let entropy = 0;
		for (const char in frequencies) {
			const p = frequencies[char] / len;
			entropy -= p * Math.log2(p);
		}

		return entropy;
	}

	/**
	 * Checks if a string is a known false positive.
	 */
	private isFalsePositive(text: string): boolean {
		return this.FALSE_POSITIVE_PATTERNS.some((regex) => regex.test(text));
	}

	/**
	 * Get statistics about scan history.
	 */
	public getStats(): {
		totalScans: number;
		secretsDetected: number;
		patternMatches: number;
		entropyMatches: number;
		avgDuration: number;
	} {
		const stats = {
			totalScans: this.history.length,
			secretsDetected: 0,
			patternMatches: 0,
			entropyMatches: 0,
			avgDuration: 0,
		};

		if (this.history.length === 0) return stats;

		let totalDuration = 0;
		for (const record of this.history) {
			if (record.result.isSecret) stats.secretsDetected++;
			if (record.result.reason === "pattern") stats.patternMatches++;
			if (record.result.reason === "entropy") stats.entropyMatches++;
			totalDuration += record.duration;
		}

		stats.avgDuration = totalDuration / this.history.length;
		return stats;
	}
}
