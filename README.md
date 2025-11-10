
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
- **Terminal-Inspired UI**: Dark/light themes, monospace typography, and command-line aesthetic
- **GitHub Secrets Scanning**: Repository analysis for exposed credentials using Gitleaks integration

---

## 🔍 Vulnerability Detection Coverage

### Advanced Detectors (20+ Categories)
- **Injection Attacks**: SQL/NoSQL/LDAP injection, OS command injection, XXE, server-side template injection
- **Authentication & Secrets**: Hardcoded credentials, AWS keys, JWT 'none' algorithm, insecure cookies
- **Web Security**: XSS, SSRF, open redirects, CORS misconfigurations, insecure direct object references
- **Cryptography**: Weak algorithms (MD5/SHA1), weak key lengths, insecure randomness
- **File Handling**: Path traversal, unrestricted file uploads, unsafe deserialization
- **Access Control**: Mass assignment vulnerabilities, missing authorization checks
- **Infrastructure**: TLS verification disabled, debug flags in production, regex DoS

### Supported Languages & File Types (30+)
- **Programming**: JavaScript/TypeScript, Python, Java, C#, PHP, Ruby, Go, Rust, Swift, C/C++, Kotlin, Scala, Perl, Lua
- **Scripts**: Shell (bash/zsh), PowerShell, Batch files
- **Configuration**: JSON, YAML, TOML, XML, environment files
- **Web**: HTML, CSS, SQL
- **Infrastructure**: Terraform, Docker, Makefiles

---

## 🛠️ Tech Stack

- **Framework**: Next.js 15.5.4, React 19.1.0, TypeScript (strict mode)
- **UI Components**: Tailwind CSS v4, Radix UI primitives, Framer Motion animations, Lucide icons
- **State Management**: Zustand 5.0.8 (flat state structure)
- **API Integration**: Multi-provider AI abstraction, Edge/Node.js runtimes
- **Security APIs**: OSV.dev (CVE lookup), Have I Been Pwned (k-anonymity), RSS aggregation
- **Development**: ESLint, PostCSS, Vercel Analytics

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
- `POST /api/secrets/scan` — GitHub repository secrets scanning

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

### Documentation
- **`/docs`** — In-application documentation and guides
- **`/docs/tui`** — Terminal UI integration instructions

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
- **AI Providers**: OpenAI, Anthropic, Google Gemini
- **UI Components**: Radix UI, Tailwind CSS, Framer Motion
- **Icons**: Lucide React

---




