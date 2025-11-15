# OneStop CYworld Guardian

🛡️ Real-time security vulnerability detection for your code.

## Features

- **Real-time Detection**: Scans your code as you type
- **Multi-language Support**: JavaScript, TypeScript, Python, Java, PHP, Go
- **Security Patterns**: Detects 10+ common vulnerabilities
- **CWE Mapping**: All findings mapped to Common Weakness Enumeration
- **Zero Configuration**: Works out of the box

## Detected Vulnerabilities

- ✅ Hardcoded API keys and secrets (CWE-798)
- ✅ AWS credentials exposure (CWE-798)
- ✅ Private key leakage (CWE-798)
- ✅ Hardcoded passwords (CWE-798)
- ✅ SQL injection patterns (CWE-89)
- ✅ Command injection (CWE-78)
- ✅ Unsafe eval() usage (CWE-95)
- ✅ Weak cryptography (MD5/SHA1) (CWE-327)
- ✅ XSS via innerHTML (CWE-79)
- ✅ JWT secret exposure (CWE-798)

## Usage

### Automatic Scanning
The extension automatically scans files when you:
- Open a file
- Edit a file
- Save a file

### Manual Commands
- `OneStop: Scan Current File` - Scan the active file
- `OneStop: Scan Entire Workspace` - Scan all supported files

## Configuration

Access settings via `File > Preferences > Settings > OneStop CYworld Guardian`

- **Enable Real-Time**: Toggle real-time scanning (default: enabled)
- **Severity Filter**: Set minimum severity to display (all/critical/high/medium)

## Example Detections

### Hardcoded API Key
```javascript
const apiKey = "sk-1234567890abcdef"; // ❌ Detected
```

### SQL Injection
```javascript
const query = "SELECT * FROM users WHERE id = " + userId; // ❌ Detected
```

### XSS Vulnerability
```javascript
element.innerHTML = userInput; // ❌ Detected
```

## Why Use This Extension?

- **Prevent Secrets Leakage**: Catch hardcoded credentials before commit
- **Early Detection**: Find vulnerabilities while coding, not in production
- **Learn Security**: Understand common security pitfalls
- **CWE Education**: Learn industry-standard vulnerability classifications

## Requirements

- Visual Studio Code 1.80.0 or higher

## Installation

1. Download the `.vsix` file from [OneStop CYworld website](https://onestop-cyworld.vercel.app/)
2. Open VS Code
3. Go to Extensions (Ctrl+Shift+X)
4. Click `...` (More Actions) → `Install from VSIX...`
5. Select the downloaded file

## About

Created as part of the OneStop CYworld security platform.
Visit [site](https://onestop-cyworld.vercel.app/) for more security tools.

## License

MIT
