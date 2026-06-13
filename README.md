# pi-secret-sentinel 🛡️

A security middleware extension for [Pi](https://pi.dev/) that prevents the accidental leakage of sensitive credentials into your codebase.

## 🚩 The Problem
AI agents are highly efficient at implementing features, but they sometimes inadvertently write hardcoded API keys, private tokens, or passwords directly into your source code or config files. Once these secrets are committed to Git, they are compromised.

## ✨ The Solution
`pi-secret-sentinel` acts as a **security guard** that intercepts filesystem-modifying tool calls (`write` and `edit`) in real-time. If it detects a secret in the payload, it **aborts the operation immediately**, preventing the secret from ever hitting your disk.

## 🔍 How it Works

The sentinel uses a dual-layer detection engine to maximize security while minimizing false positives:

### 1. High-Confidence Pattern Matching
It uses a curated library of regular expressions to identify known secret formats from popular providers:
- **GitHub**: Personal Access Tokens (`ghp_*`)
- **OpenAI**: API Keys (`sk-*`)
- **AWS**: Access Key IDs (`AKIA*`)
- **Google Cloud**: API Keys (`AIza*`)
- **Generic**: Common patterns for `api_key`, `secret`, `token`, etc.
- **SSH/RSA**: Private key headers.

### 2. Shannon Entropy Analysis
To catch custom or unknown secrets, the sentinel calculates the **Shannon Entropy** of isolated strings. High-entropy strings (those that look truly random) that exceed a specific length and complexity threshold are flagged as potential secrets, even if they don't match a known pattern.

### 3. Intelligent Filtering
To avoid annoying false positives, the sentinel automatically ignores:
- **UUIDs**: Standard 36-character unique identifiers.
- **Paths**: Absolute and relative filesystem paths.
- **Placeholders**: Strings like `YOUR_API_KEY_HERE` or `REPLACE_ME`.

## 🚀 Installation

Install via the Pi CLI:

```bash
pi install npm:pi-secret-sentinel
```

## 🛠️ Usage

Once installed, the sentinel works automatically in the background. No configuration is required.

If you attempt to write a secret to a file, Pi will stop the operation and display a high-visibility alert:

> 🔴 **SECRET DETECTED**: The write operation contains a known secret pattern.
> 
> **Security Policy**: Secrets must not be written to disk. Please use a `.env` file and reference the value via `process.env`.

## 📜 License
MIT
