"use strict";
/**
 * SecretDetector
 * Logic for identifying API keys, tokens, and sensitive strings using
 * a combination of pattern matching and Shannon Entropy.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecretDetector = void 0;
class SecretDetector {
    /**
     * High-confidence patterns for known API key formats.
     */
    PATTERNS = {
        "GitHub Personal Access Token": /ghp_[a-zA-Z0-9]{36}/,
        "OpenAI API Key": /sk-[a-zA-Z0-9]{48}/,
        "AWS Access Key ID": /AKIA[0-9A-Z]{16}/,
        "Google API Key": /AIza[0-9A-Za-z-_]{35}/,
        "Generic Secret/Token": /(api_key|secret|token|password|auth_token)[\s:=]+['"]?([^\s,;="']{16,})['"]?/i,
        "Private Key": /-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----/,
    };
    /**
     * Strings that look like secrets but are actually safe.
     */
    FALSE_POSITIVE_PATTERNS = [
        /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i, // UUID
        /^(\/|[a-zA-Z]:\\).*$/, // Absolute paths
        /^\.\/.*$/, // Relative paths
        /YOUR_API_KEY|REPLACE_ME|EXAMPLE_TOKEN/i, // Placeholders
    ];
    /**
     * Scans text for potential secrets.
     */
    scan(text) {
        if (!text)
            return { isSecret: false, reason: "none", confidence: 0 };
        // 1. Pattern Matching (Highest Confidence)
        for (const [provider, regex] of Object.entries(this.PATTERNS)) {
            if (regex.test(text)) {
                return {
                    isSecret: true,
                    reason: "pattern",
                    provider,
                    confidence: 1.0,
                };
            }
        }
        // 2. Entropy Analysis (Probabilistic)
        // We split text by common delimiters to find isolated tokens
        const tokens = text.split(/[\s,;="']+ /);
        for (const token of tokens) {
            if (token.length < 12)
                continue;
            if (this.isFalsePositive(token))
                continue;
            const entropy = this.calculateEntropy(token);
            if (entropy > 4.5) {
                return {
                    isSecret: true,
                    reason: "entropy",
                    provider: "Unknown High-Entropy String",
                    confidence: 0.7,
                };
            }
        }
        return { isSecret: false, reason: "none", confidence: 0 };
    }
    /**
     * Calculates Shannon Entropy of a string.
     * H = -sum(p(x) * log2(p(x)))
     */
    calculateEntropy(text) {
        const len = text.length;
        const frequencies = {};
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
    isFalsePositive(text) {
        return this.FALSE_POSITIVE_PATTERNS.some((regex) => regex.test(text));
    }
}
exports.SecretDetector = SecretDetector;
