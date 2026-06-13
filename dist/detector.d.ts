/**
 * SecretDetector
 * Logic for identifying API keys, tokens, and sensitive strings using
 * a combination of pattern matching and Shannon Entropy.
 */
export interface DetectionResult {
    isSecret: boolean;
    reason: "pattern" | "entropy" | "none";
    provider?: string;
    confidence: number;
}
export declare class SecretDetector {
    /**
     * High-confidence patterns for known API key formats.
     */
    private readonly PATTERNS;
    /**
     * Strings that look like secrets but are actually safe.
     */
    private readonly FALSE_POSITIVE_PATTERNS;
    /**
     * Scans text for potential secrets.
     */
    scan(text: string): DetectionResult;
    /**
     * Calculates Shannon Entropy of a string.
     * H = -sum(p(x) * log2(p(x)))
     */
    private calculateEntropy;
    /**
     * Checks if a string is a known false positive.
     */
    private isFalsePositive;
}
