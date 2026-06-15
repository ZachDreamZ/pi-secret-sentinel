import { SecretDetector } from "../extensions/detector";

describe("SecretDetector", () => {
	let detector: SecretDetector;

	beforeEach(() => {
		detector = new SecretDetector();
	});

	describe("Pattern Detection", () => {
		const cases = [
			{
				text: "my key is ghp_123456789012345678901234567890123456",
				expected: true,
				provider: "GitHub Personal Access Token",
			},
			{
				text: "sk-123456789012345678901234567890123456789012345678",
				expected: true,
				provider: "OpenAI API Key",
			},
			{
				text: "AKIA1234567890ABCDEF",
				expected: true,
				provider: "AWS Access Key ID",
			},
			{
				text: "AIzaSyA1234567890abcdefghij-klmnopqrs_tuv",
				expected: true,
				provider: "Google API Key",
			},
			{
				text: 'api_key="supersecretvalue"',
				expected: true,
				provider: "Generic Secret/Token",
			},
			{
				text: "-----BEGIN RSA PRIVATE KEY-----",
				expected: true,
				provider: "Private Key",
			},
		];

		test.each(cases)("should detect $provider from $text", ({
			text,
			expected,
			provider,
		}) => {
			const result = detector.scan(text);
			expect(result.isSecret).toBe(expected);
			if (expected) expect(result.provider).toBe(provider);
		});
	});

	describe("Entropy Detection", () => {
		it("should detect high-entropy random strings", () => {
			const randomSecret = "zX8vP2qL9mN4kS7jH1wR5tY3uI0oP6xZ"; // High entropy
			const result = detector.scan(randomSecret);
			expect(result.isSecret).toBe(true);
			expect(result.reason).toBe("entropy");
		});

		it("should ignore natural language", () => {
			const text = "This is a normal sentence with no secrets in it.";
			const result = detector.scan(text);
			expect(result.isSecret).toBe(false);
		});
	});

	describe("False Positive Mitigation", () => {
		const safeCases = [
			{ text: "550e8400-e29b-41d4-a716-446655440000", desc: "UUID" },
			{ text: "/home/user/project/file.ts", desc: "Absolute Path" },
			{ text: "C:\\Users\\Vendex\\nexus", desc: "Windows Path" },
			{ text: "YOUR_API_KEY_HERE", desc: "Placeholder" },
			{
				text: "a"
					.repeat(64)
					.replace(/[a-z]/g, (_) => Math.random().toString(16).slice(2, 3)),
				desc: "Mock Hash",
			}, // a bit simpler
			{
				text: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				desc: "SHA-256",
			},
		];

		test.each(safeCases)("should NOT flag $desc as secret", ({ text }) => {
			const result = detector.scan(text);
			expect(result.isSecret).toBe(false);
		});
	});
});
