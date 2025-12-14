
# OneStop-CYworld

---

## 🚀 Overview

**OneStop-CYworld** is a comprehensive cybersecurity workspace that combines static analysis, AI-powered code review, dependency scanning, password breach lookup, and real-time threat intelligence in a terminal-inspired interface. Designed for security professionals, developers, and DevSecOps teams who need unified vulnerability assessment tools.

---

## 🌟 Features

- **Enhanced Basic Scan**: Upload individual files or entire project folders for comprehensive static analysis across 30+ languages, detecting injection flaws, secrets, crypto issues, and access control vulnerabilities
- **AI-Assisted Code Review**: Use OpenAI, Anthropic, or Gemini for structured CWE-mapped vulnerability reports with remediation guidance
- **Dependency Vulnerability Scanner**: Parse manifests (requirements.txt, package.json, go.mod) and check for CVEs via OSV.dev with AI-generated remediation plans
- **Password Breach Lookup**: Test password exposure using Have I Been Pwned (HIBP) with privacy-preserving k-anonymity
- **Security Intelligence Feed**: Real-time cybersecurity news aggregation from multiple sources with automatic refresh
- **Encrypted API Storage**: Client-side AES-GCM encryption for API keys with secure passphrase-based decryption


---

## 🛠️ Tech Stack

- **Framework**: Next.js , TypeScript
- **State Management**: Zustand 5.0.8 
- **Security APIs**: OSV.dev (CVE lookup), Have I Been Pwned (k-anonymity), RSS aggregation
- **Development**:  Vercel Analytics

---

## ⚡ Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/christysusan/SecureAi-WebApp.git
cd SecureAi-WebApp

# 2. Install dependencies
npm install

# 3. Run the development server
npm run dev

# 4. Open in your browser
http://localhost:3000
```

### Optional: Configure AI Providers
1. Navigate to `/config` in the application
2. Set up your preferred AI provider (OpenAI, Anthropic, or Gemini)
3. API keys are encrypted client-side with AES-GCM using your passphrase

---

## 🔌 API Endpoints

### Core Scanning APIs
- `POST /api/ai/analyze` — AI-powered code analysis with multi-provider support
- `POST /api/dependency-scan` — Dependency vulnerability scanning via OSV.dev
- `GET /api/news` — Security news aggregation with RSS parsing
- `POST /api/pwned` — Password breach lookup with k-anonymity

### Utility APIs
- `GET /api/scan/start` — Initialize static analysis scan
- `GET /api/scan/status/[id]` — Retrieve scan progress and results

---

## 📱 Application Structure

### Main Features
- **`/scan`** — Basic static analysis with folder upload support
- **`/ai-assess`** — AI-powered code review with multiple providers
- **`/dependency-scanner`** — CVE detection and remediation planning
- **`/pass-strength`** — Password breach checking with HIBP integration
- **`/news`** — Real-time cybersecurity intelligence feed
- **`/config`** — AI provider configuration and API key management

---

## � Key Architectural Patterns

### Multi-Provider AI Integration
```typescript
// Provider-agnostic analysis with normalized responses
const provider = aiConfig.provider || "openai"
const analysis = await analyzeCode(code, provider)
// Returns: { summary, vulnerabilities: [{ id, title, severity, rule, line, ... }] }
```

### Client-Side Encryption
```typescript
// API keys encrypted with AES-GCM before localStorage storage
const encrypted = await encryptApiKey(apiKey, passphrase)
// Format: { salt: base64, iv: base64, cipher: base64 }
```



---

## 🔒 Security Features

- **Client-Side Encryption**: All API keys encrypted with user-provided passphrases
- **K-Anonymity**: Password checks use partial hashes to preserve privacy
- **CWE Mapping**: All vulnerability findings mapped to Common Weakness Enumeration
- **Rate Limiting**: Built-in handling for API rate limits with graceful degradation
- **Secure Defaults**: HTTPS endpoints, secure cookie flags, input validation

---


## 🌟 Acknowledgments

- **Security Data**: OSV.dev, Have I Been Pwned, CISA
- **UI Components**: Radix UI, Tailwind CSS, Framer Motion
- **Icons**: Lucide React

---




