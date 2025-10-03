
# SecureAI-Code Web

<p align="center">
	<img src="public/placeholder-logo.png" alt="SecureAI Logo" width="120" />
</p>

---

## 🚀 Overview

**SecureAI-Code Web** is a modern, terminal-inspired web platform for automated cybersecurity scanning, AI-assisted code review, and hands-on security education through interactive games. It combines static analysis, machine learning, and gamification to help users learn, assess, and improve code security.

---

## 🌟 Features

- **Automated Vulnerability Scanning**: Detect SSRF, command injection, XSS, insecure config, and more.
- **AI-Assisted Code Review**: Integrate with OpenAI, Anthropic, or Gemini for CWE-mapped vulnerability reports and remediation.
- **Dependency Vulnerability Scanner**: Parse manifests (requirements.txt, package.json, go.mod) and check for CVEs via OSV.dev.
- **Password Breach Lookup**: Check password strength and exposure using Have I Been Pwned (HIBP) API with privacy-preserving k-anonymity.
- **Interactive Security Games**: Learn cybersecurity concepts through games like CyberSnake Quiz, Password Defense, Phishing Detective, Firewall Defense, Crypto Puzzles, CTF Mini, Threat Hunter Lab, and Incident Response Simulator.
- **Configurable AI Providers**: Easily switch between AI models and set analysis depth.
- **Modern UI/UX**: Terminal-inspired design, dark/light themes, and responsive layout.

---

## 🕹️ Security Games

| Game                     | Description                                                      | Difficulty   |
|--------------------------|------------------------------------------------------------------|--------------|
| CyberSnake Quiz          | Learn security through a snake game with technical questions      | Beginner     |
| Password Defense         | Defend against password attacks by creating stronger passwords    | Intermediate |
| Phishing Detective       | Analyze emails to spot phishing and social engineering            | Intermediate |
| Firewall Defense         | Configure firewall rules to block malicious network traffic       | Advanced     |
| Crypto Puzzles           | Solve encryption challenges and learn cryptographic principles    | Advanced     |
| CTF Mini                 | Capture-the-flag: find hidden flags in file systems              | Expert       |
| Threat Hunter Lab        | Inspect logs, flag threats, and defend the SOC dashboard          | Advanced     |
| Incident Response Sim    | Lead crisis decisions in simulated security incidents             | Expert       |

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
- `/api/games/[gameId]/score` — Game scoring endpoints
- `/api/games/leaderboard/[gameId]` — Leaderboards
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


