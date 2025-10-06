
# OneStop-CYworld


---

## 🚀 Overview

**OneStop-CYworld** is a terminal-inspired security operations workspace that unifies automated scanning, AI-assisted code review, and real-time threat intelligence. It blends static analysis with provider-neutral AI assessments so teams can detect vulnerabilities, triage alerts, and stay ahead of emerging threats from a single pane of glass.

---

## 🌟 Features

- **Automated Vulnerability Scanning**: Detect SSRF, command injection, XSS, insecure config, and more with instant heuristics.
- **AI-Assisted Code Review**: Use OpenAI, Anthropic, or Gemini for CWE-mapped reports and rich remediation guidance.
- **Dependency Vulnerability Scanner**: Parse manifests (requirements.txt, package.json, go.mod) and check for CVEs via OSV.dev.
- **Password Breach Lookup**: Test password exposure using Have I Been Pwned (HIBP) with privacy-preserving k-anonymity.
- **Security Intelligence Feed**: Aggregated advisories from CISA, BleepingComputer, and The Hacker News with 30-minute refreshes.
- **Configurable AI Providers**: Easily swap models, tune confidence, and work with encrypted API storage.
- **Modern UI/UX**: Terminal-inspired design, dark/light themes, and responsive layout.

---

## 🛠️ Tech Stack

- **Framework**: Next.js 15, React 19
- **UI**: Tailwind CSS, Radix UI, Framer Motion
- **State**: Zustand
- **AI Providers**: OpenAI, Anthropic, Gemini (configurable)
- **Security APIs**: OSV.dev, Have I Been Pwned
- **Deployment**: Vercel

---

## ⚡ Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Run the development server
npm run dev

# 3. Open in your browser
http://localhost:3000
```

---

## 🔌 API Endpoints

- `/api/ai/analyze` — AI-powered code analysis
- `/api/dependency-scan` — Dependency manifest scanning
- `/api/pwned` — Password breach lookup (HIBP)
- `/api/news` — Security news aggregation (CISA, BleepingComputer, The Hacker News)
- `/api/scan/start` — Start a new scan
- `/api/scan/status/[id]` — Scan status

---

## 📚 Documentation

- In-app docs: `/docs`
- TUI/CLI integration: `/docs/tui`
- Configuration: `/config`

---

## 👩‍💻 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## 📝 License

This project is for research and educational use. See [LICENSE](LICENSE) for details.

---


