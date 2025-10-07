"use client"

import { useRef, useState } from "react"
import { AnimatePresence, motion } from "framer-motion"
import type { LucideIcon } from "lucide-react"
import {
  AlertCircle,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileCode,
  FileText,
  Info,
  Play,
  Shield,
  ShieldCheck,
  Upload,
} from "lucide-react"

import { Header } from "@/components/layout/header"
import { TerminalBox } from "@/components/layout/terminal-box"
import { ProgressBar } from "@/components/ui/progress-bar"

type Severity = "critical" | "high" | "medium" | "low"

type Language =
  | "c"
  | "csharp"
  | "cpp"
  | "config"
  | "go"
  | "java"
  | "javascript"
  | "php"
  | "python"
  | "ruby"
  | "rust"
  | "swift"
  | "typescript"
  | "kotlin"
  | "scala"
  | "perl"
  | "lua"
  | "shell"
  | "powershell"
  | "batch"
  | "sql"
  | "xml"
  | "html"
  | "css"
  | "json"
  | "yaml"
  | "toml"
  | "env"
  | "terraform"
  | "docker"
  | "generic"

interface CodeFrameLine {
  number: number
  content: string
  isHighlight: boolean
}

interface ScanResult {
  file: string
  line: number
  severity: Severity
  type: string
  message: string
  rule: string
  remediation: string
  code: CodeFrameLine[]
}

interface ScanStats {
  filesScanned: number
  totalLines: number
  totalIssues: number
  critical: number
  high: number
  medium: number
  low: number
}

interface DetectorContext {
  line: string
  lines: string[]
  lineNumber: number
  language: Language
  fileName: string
}

interface Detector {
  id: string
  type: string
  severity: Severity
  rule: string
  message: string
  remediation: string
  appliesTo?: Language[]
  context?: number
  test: (ctx: DetectorContext) => boolean
}

function GitHubSecretsScan() {
  const [repoUrl, setRepoUrl] = useState("")
  const [includeHistory, setIncludeHistory] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<Array<{ file: string; line: number | null; rule: string; description: string; match?: string; severity?: string }>>([])
  const [showInfo, setShowInfo] = useState(false)
  const [hasScanned, setHasScanned] = useState(false)
  const [usedGitleaks, setUsedGitleaks] = useState<boolean | null>(null)
  const [durationMs, setDurationMs] = useState<number | null>(null)

  const runScan = async () => {
    setError(null)
    setLoading(true)
    setResults([])
    setHasScanned(false)
    setUsedGitleaks(null)
    setDurationMs(null)
    try {
      const start = Date.now()
      const res = await fetch("/api/secrets/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl, includeHistory }),
      })
      const data = await res.json()
      if (!res.ok || data?.error) {
        throw new Error(data?.message || "Secrets scan failed")
      }
      setResults(data.findings || [])
      setUsedGitleaks(Boolean(data.usedGitleaks))
      setDurationMs(Date.now() - start)
      setHasScanned(true)
    } catch (e: any) {
      setError(e?.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  const download = (type: "json" | "csv" | "sarif") => {
    const a = document.createElement("a")
    let blob: Blob
    if (type === "json") {
      blob = new Blob([JSON.stringify({ findings: results }, null, 2)], { type: "application/json" })
      a.download = "secrets-findings.json"
    } else if (type === "csv") {
      const header = "file,line,rule,description,match,severity\n"
      const rows = results.map(r => [r.file, r.line ?? "", r.rule, r.description, r.match ?? "", r.severity ?? ""].map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n")
      blob = new Blob([header + rows], { type: "text/csv" })
      a.download = "secrets-findings.csv"
    } else {
      const sarif = {
        version: "2.1.0",
        $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        runs: [
          {
            tool: { driver: { name: "OneStop-CYworld Secrets Scan", rules: [] as any[] } },
            results: results.map(r => ({
              ruleId: r.rule,
              message: { text: r.description },
              locations: [{
                physicalLocation: {
                  artifactLocation: { uri: r.file },
                  region: { startLine: r.line ?? 1 }
                }
              }]
            }))
          }
        ]
      }
      blob = new Blob([JSON.stringify(sarif, null, 2)], { type: "application/sarif+json" })
      a.download = "secrets-findings.sarif"
    }
    a.href = URL.createObjectURL(blob)
    a.click()
    URL.revokeObjectURL(a.href)
  }

  return (
    <div className="space-y-3 rounded-lg border border-border/60 bg-card/60 p-3">
      <div className="flex items-center justify-between gap-2">
        <label className="text-sm font-semibold text-foreground">GitHub Secrets Scan</label>
        <button onClick={() => setShowInfo(true)} className="text-xs text-brand underline underline-offset-2">What’s this?</button>
      </div>
      <label className="text-xs font-medium text-foreground/80">Repository URL</label>
      <input
        type="url"
        placeholder="https://github.com/owner/repo"
        value={repoUrl}
        onChange={(e) => setRepoUrl(e.target.value)}
        className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/70 focus:outline-none focus:ring-2 focus:ring-brand/40"
      />
      <label className="flex items-center gap-2 text-xs text-muted-foreground">
        <input type="checkbox" checked={includeHistory} onChange={(e) => setIncludeHistory(e.target.checked)} />
        Scan recent commit history (slower, finds removed secrets)
      </label>
      <motion.button
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
        onClick={runScan}
        disabled={loading || !repoUrl}
        className="flex items-center justify-center gap-2 rounded-lg border border-brand/40 bg-brand/10 px-4 py-2 text-sm font-medium text-brand transition-colors hover:bg-brand/15 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {loading ? "Scanning…" : "Run Secrets Scan with Gitleaks"}
      </motion.button>
      {results.length > 0 && (
        <div className="flex flex-wrap gap-2">
          <button onClick={() => download("json")} className="rounded border border-border bg-surface px-2 py-1 text-xs">Download JSON</button>
          <button onClick={() => download("csv")} className="rounded border border-border bg-surface px-2 py-1 text-xs">Download CSV</button>
          <button onClick={() => download("sarif")} className="rounded border border-border bg-surface px-2 py-1 text-xs">Download SARIF</button>
        </div>
      )}
      {error && <div className="rounded border border-[#E37769] bg-[#E37769]/10 p-2 text-xs text-[#355952]">{error}</div>}
      {hasScanned && !error && results.length === 0 && (
        <div className="rounded border border-[#355952] bg-[#355952]/10 p-2 text-xs text-[#355952]">
          No secrets found in the scanned scope{includeHistory ? " (including recent history)" : " (shallow scan)"}.
          {usedGitleaks && (
            <span className="ml-1 text-[#355952]/80">Scanner: Gitleaks</span>
          )}
          {typeof durationMs === "number" && (
            <span className="ml-1 text-[#355952]/80">• Duration: {Math.max(1, Math.round(durationMs/1000))}s</span>
          )}
        </div>
      )}
      {hasScanned && !error && results.length > 0 && (
        <div className="rounded border border-border/60 bg-background p-2 text-xs text-muted-foreground">
          <span className="text-foreground font-medium">{results.length}</span> findings{usedGitleaks ? " • Scanner: Gitleaks" : ""}
          {typeof durationMs === "number" && <span> • Duration: {Math.max(1, Math.round(durationMs/1000))}s</span>}
        </div>
      )}
      {results.length > 0 && (
        <div className="mt-2 max-h-60 overflow-auto rounded-lg border border-border/60 bg-background p-2">
          <div className="mb-2 text-xs font-semibold text-foreground">Findings ({results.length})</div>
          <ul className="space-y-1 text-xs text-muted-foreground">
            {results.slice(0, 50).map((f, i) => (
              <li key={i} className="rounded border border-border/40 bg-background/40 p-2">
                <div className="font-mono text-[11px] text-foreground">{f.file}:{f.line ?? "?"}</div>
                <div className="text-[11px]">{f.rule} — {f.description}</div>
                {f.match && <div className="text-[11px] text-brand">match: {f.match}</div>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Info Modal */}
      {showInfo && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
          <div className="max-w-lg rounded-lg border border-border bg-card p-4 text-sm text-foreground shadow-xl">
            <div className="mb-2 font-semibold">Shallow scan vs. history scan</div>
            <ul className="mb-2 list-disc space-y-1 pl-5 text-muted-foreground">
              <li><span className="font-medium text-foreground">Shallow scan</span>: Scans current repository files only (fast). Best for quick checks.</li>
              <li><span className="font-medium text-foreground">History scan</span>: Also looks through recent commit history (slower). Finds secrets that were committed and later removed.</li>
            </ul>
            <div className="mb-2 text-xs text-muted-foreground">
              Estimated runtime: shallow (seconds), history (tens of seconds to minutes) depending on repo size.
            </div>
            <div className="text-right">
              <button onClick={() => setShowInfo(false)} className="rounded border border-border bg-surface px-3 py-1 text-xs">Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

const detectors: Detector[] = [
  {
    id: "dynamic-eval",
    type: "Dynamic Code Execution",
    severity: "critical",
    rule: "CWE-94",
    message: "Dynamic evaluation of strings enables attackers to execute arbitrary code.",
    remediation: "Remove eval-style calls and use safe interpreters or explicit command allowlists.",
    appliesTo: ["javascript", "typescript", "python", "php", "ruby"],
    test: ({ line }) => /\beval\s*\(/.test(line),
  },
  {
    id: "command-exec",
    type: "OS Command Injection",
    severity: "critical",
    rule: "CWE-78",
    message: "User input reaching system command execution can lead to remote code execution.",
    remediation: "Avoid shell invocation with user data; use safe library calls or strict argument validation.",
    appliesTo: ["javascript", "typescript", "python", "php", "java", "csharp", "ruby"],
    test: ({ line }) =>
      /(child_process\.exec(Sync)?|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|system\(|exec\(|popen\(|shell_exec)/i.test(line),
  },
  {
    id: "hardcoded-secret",
    type: "Credential Exposure",
    severity: "high",
    rule: "CWE-798",
    message: "Possible hardcoded credential or secret detected in source.",
    remediation: "Store secrets in environment variables or a secrets manager and inject at runtime.",
    appliesTo: ["generic"],
    test: ({ line }) =>
      /\b(pass(word|phrase)?|api[_-]?key|secret|token)\b\s*[:=]\s*["'][^"']{4,}["']/i.test(line) &&
      !/process\.env|os\.environ|Environment\.GetEnvironmentVariable/i.test(line),
  },
  {
    id: "aws-key",
    type: "Cloud Credential Leak",
    severity: "high",
    rule: "CWE-200",
    message: "AWS-style access key detected in code.",
    remediation: "Rotate the credential immediately and load keys from secured configuration stores only.",
    appliesTo: ["generic"],
    test: ({ line }) => /AKIA[0-9A-Z]{16}/.test(line),
  },
  {
    id: "sql-string",
    type: "SQL Injection",
    severity: "high",
    rule: "CWE-89",
    message: "SQL query appears to be assembled via string concatenation.",
    remediation: "Use parameterized queries, prepared statements, or ORM query builders.",
    appliesTo: ["javascript", "typescript", "python", "php", "java", "csharp", "ruby"],
    test: ({ line }) => {
      const normalized = line.replace(/`|"|'/g, "\"")
      return /\b(SELECT|INSERT|UPDATE|DELETE)\b/i.test(normalized) && /(\+|\$\{|concat\s*\()/i.test(normalized)
    },
  },
  {
    id: "innerhtml",
    type: "Cross-Site Scripting",
    severity: "high",
    rule: "CWE-79",
    message: "User-controlled content assigned to innerHTML without sanitization.",
    remediation: "Use textContent or a vetted sanitizer before injecting HTML.",
    appliesTo: ["javascript", "typescript"],
    test: ({ line }) => /\.innerHTML\s*=\s*.*(\+|\$\{|template\s*`)/i.test(line),
  },
  {
    id: "weak-hash",
    type: "Weak Cryptography",
    severity: "medium",
    rule: "CWE-327",
    message: "Weak hash algorithm (MD5/SHA1) detected.",
    remediation: "Replace with SHA-256/512 or a modern password hashing function such as bcrypt or Argon2.",
    appliesTo: ["javascript", "typescript", "python", "php", "java", "csharp", "ruby"],
    test: ({ line }) =>
      /(md5|sha1)\s*\(/i.test(line) || /hashlib\.(md5|sha1)/i.test(line) || /createHash\(['"]?(md5|sha1)/i.test(line),
  },
  {
    id: "insecure-random",
    type: "Weak Randomness",
    severity: "medium",
    rule: "CWE-338",
    message: "Predictable random generator used for security-sensitive value.",
    remediation: "Use cryptographically secure generators like crypto.randomBytes, os.urandom, or java.security.SecureRandom.",
    appliesTo: ["javascript", "typescript", "python", "php", "ruby", "java"],
    test: ({ line, language }) => {
      if (/(token|secret|otp|password|key)/i.test(line) === false) return false
      if (["javascript", "typescript"].includes(language)) return /Math\.random\s*\(/.test(line)
      if (language === "python") return /random\.random\s*\(/.test(line)
      if (language === "php") return /rand\s*\(/i.test(line)
      if (language === "ruby") return /Random\.rand/i.test(line)
      if (language === "java") return /new\s+Random\s*\(/.test(line)
      return false
    },
  },
  {
    id: "http-url",
    type: "Insecure Transport",
    severity: "low",
    rule: "CWE-319",
    message: "Plain HTTP URL detected; traffic may be intercepted.",
    remediation: "Prefer HTTPS endpoints; if using HTTP for testing, guard with environment checks.",
    appliesTo: ["generic"],
    test: ({ line }) => {
      const match = line.match(/http:\/\/([^\"'`]+)/i)
      if (!match) return false
      return !/(localhost|127\.0\.0\.1|0\.0\.0\.0)/i.test(match[1])
    },
  },
  {
    id: "debug-mode",
    type: "Debug Configuration",
    severity: "low",
    rule: "CWE-489",
    message: "Debug or verbose mode appears to be enabled.",
    remediation: "Disable debug configurations in production deployments.",
    appliesTo: ["python", "javascript", "typescript", "php", "ruby"],
    test: ({ line }) => /(DEBUG|debug)\s*[:=]\s*(true|1)/.test(line),
  },
  {
    id: "unsafe-deserialize",
    type: "Unsafe Deserialization",
    severity: "high",
    rule: "CWE-502",
    message: "Potentially unsafe deserialization routine detected.",
    remediation: "Use safe loaders (e.g., yaml.safe_load) or validate input before deserializing.",
    appliesTo: ["python", "ruby"],
    test: ({ line }) => /pickle\.load|yaml\.load\s*\(/i.test(line) && !/SafeLoader|safe_load/i.test(line),
  },
  {
    id: "ssrf-request",
    type: "Server-Side Request Forgery",
    severity: "high",
    rule: "CWE-918",
    message: "User-controlled URL is used in a server-side HTTP request.",
    remediation: "Validate outbound destinations against an allowlist and avoid forwarding raw user URLs.",
    appliesTo: ["javascript", "typescript", "python", "php", "ruby", "java", "go"],
    test: ({ line }) => {
      const requestCall = /(fetch\(|axios\.(get|post|put)|request\.(get|post)|requests\.(get|post)|http\.get|urllib\.request)/i.test(line)
      if (!requestCall) return false
      return /(req\.(body|query|params)|request\.(GET|POST)|ctx\.|input\(|\$_(GET|POST)|params\[)/i.test(line)
    },
  },
  {
    id: "path-traversal",
    type: "Path Traversal",
    severity: "high",
    rule: "CWE-22",
    message: "Detected traversal sequences in file system access.",
    remediation: "Normalize and restrict file paths to approved directories before accessing the file system.",
    appliesTo: ["javascript", "typescript", "python", "php", "ruby", "java", "csharp", "go"],
    test: ({ line }) => {
      if (!/(fs\.(readFile|createReadStream|writeFile)|open\s*\(|File\.open|fopen|os\.open|path\.join|Files\.)/i.test(line)) {
        return false
      }
      if (!/(\.\.[\\/])/.test(line)) {
        return false
      }
      return /(req\.|request\.|ctx\.|input\(|\$_(GET|POST)|params\[)/i.test(line)
    },
  },
  {
    id: "wildcard-cors",
    type: "Overly Permissive CORS",
    severity: "medium",
    rule: "CWE-284",
    message: "Cross-origin policy allows any origin, enabling CSRF-style attacks.",
    remediation: "Lock CORS configuration to trusted origins and avoid using wildcard policies in production.",
    appliesTo: ["javascript", "typescript", "python", "ruby", "php"],
    test: ({ line }) =>
      /Access-Control-Allow-Origin\s*[:=]\s*["']\*["']/.test(line) || /cors\((.|\n)*origin:\s*["']\*["']/i.test(line),
  },
  {
    id: "insecure-tls",
    type: "TLS Verification Disabled",
    severity: "medium",
    rule: "CWE-295",
    message: "TLS certificate verification is disabled for an outbound request.",
    remediation: "Enable certificate validation or pinning to prevent man-in-the-middle attacks.",
    appliesTo: ["javascript", "typescript", "python", "ruby", "java"],
    test: ({ line }) =>
      /verify\s*=\s*False/.test(line) || /rejectUnauthorized\s*:\s*false/.test(line) || /setHostnameVerifier\(\s*\(hostname, session\) -> true\s*\)/i.test(line),
  },
  {
    id: "insecure-cookie",
    type: "Insecure Cookie Settings",
    severity: "medium",
    rule: "CWE-614",
    message: "Cookies lack secure or HTTPOnly attributes, increasing hijack risk.",
    remediation: "Mark authentication cookies as Secure, HttpOnly, and SameSite=Strict/Lax where possible.",
    appliesTo: ["javascript", "typescript", "python", "ruby", "php"],
    test: ({ line }) =>
      /(res\.cookie|cookies\.set|Set-Cookie|set_cookie\s*\()/i.test(line) && /secure\s*[:=]\s*(false|0)/i.test(line),
  },
  {
    id: "jwt-none-alg",
    type: "JWT Algorithm None",
    severity: "high",
    rule: "CWE-345",
    message: "JWT configured with 'none' algorithm disables signature verification.",
    remediation: "Use a secure signing algorithm like HS256, RS256, or ES256 for JWT tokens.",
    appliesTo: ["javascript", "typescript", "python", "java", "csharp", "php"],
    test: ({ line }) => /algorithm\s*[:=]\s*["']none["']/i.test(line) && /jwt|token/i.test(line),
  },
  {
    id: "xml-external-entity",
    type: "XML External Entity",
    severity: "high",
    rule: "CWE-611",
    message: "XML parser may be vulnerable to XXE attacks if external entities are enabled.",
    remediation: "Disable external entity processing and DTD validation in XML parsers.",
    appliesTo: ["java", "csharp", "python", "php"],
    test: ({ line }) => 
      /(DocumentBuilder|XMLReader|XmlReader|lxml\.etree|SimpleXMLElement)/i.test(line) && 
      !/setFeature.*EXTERNAL_GENERAL_ENTITIES.*false|disable_entities|XMLParser\(resolve_entities=False\)/i.test(line),
  },
  {
    id: "ldap-injection",
    type: "LDAP Injection",
    severity: "high",
    rule: "CWE-90",
    message: "LDAP query constructed with unsanitized user input.",
    remediation: "Use parameterized LDAP queries or escape special LDAP characters in user input.",
    appliesTo: ["java", "csharp", "python", "php"],
    test: ({ line }) => 
      /ldap.*search|LdapConnection|DirectoryEntry/i.test(line) && 
      /(req\.|request\.|params\[|\$_(GET|POST)|input\(|ctx\.)/i.test(line),
  },
  {
    id: "nosql-injection",
    type: "NoSQL Injection",
    severity: "high",
    rule: "CWE-943",
    message: "NoSQL query vulnerable to injection via unsanitized user input.",
    remediation: "Use parameterized queries, validate input types, and sanitize user data before database operations.",
    appliesTo: ["javascript", "typescript", "python", "php", "java"],
    test: ({ line }) => 
      /(find\(|findOne\(|aggregate\(|match\s*:|where\s*:)/i.test(line) && 
      /(req\.|request\.|params\[|\$_(GET|POST)|input\(|ctx\.)/i.test(line) &&
      /(mongo|mongoose|pymongo)/i.test(line),
  },
  {
    id: "open-redirect",
    type: "Open Redirect",
    severity: "medium",
    rule: "CWE-601",
    message: "Application redirects to user-controlled URL without validation.",
    remediation: "Validate redirect URLs against an allowlist or use relative URLs only.",
    appliesTo: ["javascript", "typescript", "python", "php", "java", "csharp"],
    test: ({ line }) => 
      /(redirect\(|location\s*=|Location:|sendRedirect|Response\.Redirect)/i.test(line) && 
      /(req\.|request\.|params\[|\$_(GET|POST)|input\(|ctx\.)/i.test(line),
  },
  {
    id: "file-upload-unrestricted",
    type: "Unrestricted File Upload",
    severity: "high",
    rule: "CWE-434",
    message: "File upload without proper extension or content type validation.",
    remediation: "Validate file extensions, MIME types, and scan uploaded files for malicious content.",
    appliesTo: ["javascript", "typescript", "python", "php", "java", "csharp"],
    test: ({ line }) => 
      /(multer|express-fileupload|upload|move_uploaded_file|Files\.SaveAs)/i.test(line) && 
      !/\.(pdf|jpg|jpeg|png|gif|txt|csv)["']|allowedTypes|ALLOWED_EXTENSIONS|contentType.*check/i.test(line),
  },
  {
    id: "crypto-weak-key",
    type: "Weak Cryptographic Key",
    severity: "medium",
    rule: "CWE-326",
    message: "Cryptographic operation uses a weak or short key length.",
    remediation: "Use key lengths of at least 2048 bits for RSA, 256 bits for AES, or 256 bits for ECDSA.",
    appliesTo: ["javascript", "typescript", "python", "java", "csharp"],
    test: ({ line }) => 
      /(generateKeyPair|RSA.*1024|AES.*128|DES[^C]|RC4|keySize.*1024)/i.test(line),
  },
  {
    id: "regex-dos",
    type: "Regular Expression DoS",
    severity: "medium", 
    rule: "CWE-1333",
    message: "Complex regex pattern may be vulnerable to ReDoS attacks.",
    remediation: "Avoid nested quantifiers and alternation with overlapping patterns in user-facing regex.",
    appliesTo: ["javascript", "typescript", "python", "php", "java", "csharp"],
    test: ({ line }) => 
      /new RegExp\(|re\.compile\(|Pattern\.compile\(|preg_match\(/i.test(line) && 
      /(\(.*\+.*\)|(\*.*\+)|(\+.*\*)|(\{.*,.*\}.*\+))/.test(line),
  },
  {
    id: "template-injection",
    type: "Server-Side Template Injection",
    severity: "critical",
    rule: "CWE-94",
    message: "Template engine processes user input without proper sanitization.",
    remediation: "Use sandboxed template environments and avoid rendering user-controlled template strings.",
    appliesTo: ["python", "java", "javascript", "typescript", "php"],
    test: ({ line }) => 
      /(render_template_string|Template\(|Velocity\.|Freemarker|template\.render|eval\(|compile\()/i.test(line) && 
      /(req\.|request\.|params\[|\$_(GET|POST)|input\(|ctx\.)/i.test(line),
  },
  {
    id: "mass-assignment",
    type: "Mass Assignment",
    severity: "medium",
    rule: "CWE-915",
    message: "Object properties assigned directly from user input without filtering.",
    remediation: "Use allowlists to specify which properties can be mass-assigned or use explicit assignment.",
    appliesTo: ["javascript", "typescript", "python", "ruby", "php"],
    test: ({ line }) => 
      /(Object\.assign|spread.*req\.|\.update\(req\.|\.save\(req\.|strong_parameters)/i.test(line) && 
      !/permit\(|allowed_fields|whitelist/i.test(line),
  },
  {
    id: "information-disclosure",
    type: "Information Disclosure",
    severity: "low",
    rule: "CWE-200",
    message: "Potentially sensitive information exposed in logs or error messages.",
    remediation: "Avoid logging sensitive data and use generic error messages for user-facing errors.",
    appliesTo: ["generic"],
    test: ({ line }) => 
      /(console\.log|print\(|logger\.|error\(|exception\()/i.test(line) && 
      /(password|secret|token|api_key|private_key|credit_card)/i.test(line),
  },
  {
    id: "insecure-direct-object-reference",
    type: "Insecure Direct Object Reference",
    severity: "medium",
    rule: "CWE-639",
    message: "Direct object reference without authorization check detected.",
    remediation: "Implement proper authorization checks before accessing objects by ID.",
    appliesTo: ["javascript", "typescript", "python", "php", "java"],
    test: ({ line }) => 
      /(findById|get.*ById|SELECT.*WHERE.*id|\/api\/.*\/\$\{|\/\$\{id\})/i.test(line) && 
      !/auth|permission|check|verify|authorize/i.test(line),
  },
]



const severityStyles: Record<Severity, { accent: string; badge: string; button: string; icon: string }> = {
  critical: {
    accent: "ring-1 ring-red-200",
    badge: "border border-red-400 bg-red-50 text-red-700",
    button: "bg-[#E37769] text-[#FAF6E7] hover:bg-[#E37769]/90",
    icon: "text-[#E37769]",
  },
  high: {
    accent: "ring-1 ring-red-200",
    badge: "border border-[#E37769] bg-[#E37769]/10 text-[#355952]",
    button: "bg-[#E37769] text-[#FAF6E7] hover:bg-[#E37769]/90",
    icon: "text-[#E37769]",
  },
  medium: {
    accent: "ring-1 ring-amber-200",
    badge: "border border-[#355952]/30 bg-[#355952]/5 text-[#355952]",
    button: "bg-[#355952] text-[#FAF6E7] hover:bg-[#355952]/90",
    icon: "text-[#355952]",
  },
  low: {
    accent: "ring-1 ring-blue-200",
    badge: "border border-[#355952]/20 bg-[#355952]/5 text-[#355952]/80",
    button: "bg-[#355952]/70 text-[#FAF6E7] hover:bg-[#355952]/80",
    icon: "text-[#355952]/70",
  },
}

const severityIcons: Record<Severity, LucideIcon> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
}

const getLanguageFromFileName = (fileName: string): Language => {
  const extension = fileName.split(".").pop()?.toLowerCase() ?? ""
  const basename = fileName.toLowerCase()
  
  // Check for specific filenames first
  if (basename === "dockerfile" || basename.startsWith("dockerfile.")) return "generic"
  if (basename === "jenkinsfile" || basename === "vagrantfile" || basename === "makefile") return "generic"
  
  switch (extension) {
    case "js":
    case "jsx":
    case "mjs":
    case "cjs":
      return "javascript"
    case "ts":
    case "tsx":
    case "mts":
    case "cts":
      return "typescript"
    case "py":
    case "pyw":
    case "pyi":
      return "python"
    case "php":
    case "php3":
    case "php4":
    case "php5":
    case "phtml":
      return "php"
    case "java":
    case "jsp":
    case "jspx":
      return "java"
    case "cs":
    case "csx":
    case "vb":
      return "csharp"
    case "rb":
    case "rbw":
    case "rake":
    case "gemspec":
      return "ruby"
    case "go":
    case "mod":
      return "go"
    case "rs":
      return "rust"
    case "swift":
      return "swift"
    case "c":
    case "h":
      return "c"
    case "cpp":
    case "cc":
    case "cxx":
    case "c++":
    case "hpp":
    case "hxx":
    case "h++":
      return "cpp"
    case "kt":
    case "kts":
      return "kotlin"
    case "scala":
    case "sc":
      return "scala"
    case "pl":
    case "pm":
    case "perl":
      return "perl"
    case "lua":
      return "lua"
    case "sh":
    case "bash":
    case "zsh":
    case "fish":
      return "shell"
    case "ps1":
    case "psm1":
    case "psd1":
      return "powershell"
    case "bat":
    case "cmd":
      return "batch"
    case "sql":
    case "mysql":
    case "pgsql":
      return "sql"
    case "xml":
    case "xsd":
    case "xsl":
    case "xslt":
      return "xml"
    case "html":
    case "htm":
    case "xhtml":
      return "html"
    case "css":
    case "scss":
    case "sass":
    case "less":
      return "css"
    case "json":
    case "jsonc":
    case "json5":
      return "json"
    case "yaml":
    case "yml":
      return "yaml"
    case "toml":
      return "toml"
    case "ini":
    case "cfg":
    case "conf":
    case "config":
      return "config"
    case "env":
    case "environment":
      return "env"
    case "tf":
    case "tfvars":
    case "hcl":
      return "terraform"
    case "dockerfile":
      return "docker"
    default:
      return "generic"
  }
}

const createCodeFrame = (lines: string[], lineNumber: number, radius = 2): CodeFrameLine[] => {
  const start = Math.max(0, lineNumber - radius)
  const end = Math.min(lines.length - 1, lineNumber + radius)
  const frame: CodeFrameLine[] = []

  for (let i = start; i <= end; i += 1) {
    frame.push({
      number: i + 1,
      content: lines[i]?.replace(/\t/g, "  ") ?? "",
      isHighlight: i === lineNumber,
    })
  }

  return frame
}

const analyzeContent = (fileName: string, rawContent: string) => {
  const normalized = rawContent.replace(/\r\n/g, "\n")
  const lines = normalized.split("\n")
  const language = getLanguageFromFileName(fileName)
  const results: ScanResult[] = []

  lines.forEach((line, index) => {
    detectors.forEach((detector) => {
      if (detector.appliesTo && !detector.appliesTo.includes("generic") && !detector.appliesTo.includes(language)) {
        return
      }

      if (detector.test({ line, lines, lineNumber: index, language, fileName })) {
        results.push({
          file: fileName,
          line: index + 1,
          severity: detector.severity,
          type: detector.type,
          message: detector.message,
          rule: detector.rule,
          remediation: detector.remediation,
          code: createCodeFrame(lines, index, detector.context ?? 2),
        })
      }
    })
  })

  return {
    results,
    totalLines: lines.length,
  }
}

const buildStats = (issues: ScanResult[], filesScanned: number, totalLines: number): ScanStats => ({
  filesScanned,
  totalLines,
  totalIssues: issues.length,
  critical: issues.filter((issue) => issue.severity === "critical").length,
  high: issues.filter((issue) => issue.severity === "high").length,
  medium: issues.filter((issue) => issue.severity === "medium").length,
  low: issues.filter((issue) => issue.severity === "low").length,
})

const baseCardClass = "rounded-xl border border-border bg-card p-4 shadow-sm"

const formatNumber = (value: number) => value.toLocaleString()

export default function ScanPage() {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [progress, setProgress] = useState(0)
  const [isScanning, setIsScanning] = useState(false)
  const [scanComplete, setScanComplete] = useState(false)
  const [currentFile, setCurrentFile] = useState("")
  const [results, setResults] = useState<ScanResult[]>([])
  const [folderMode, setFolderMode] = useState(false)
  const [stats, setStats] = useState<ScanStats>({
    filesScanned: 0,
    totalLines: 0,
    totalIssues: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  })
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | "all">("all")

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files
    if (!files || files.length === 0) return

    setIsScanning(true)
    setProgress(0)
    setScanComplete(false)
    setResults([])

    const uploads = Array.from(files)
    let allResults: ScanResult[] = []
    let processedFiles = 0
    let totalLines = 0

    for (const file of uploads) {
      setCurrentFile(file.name)

      try {
        const content = await file.text()
        const { results: fileResults, totalLines: fileLines } = analyzeContent(file.name, content)
        allResults = allResults.concat(fileResults)
        totalLines += fileLines
      } catch (error) {
        console.error(`Failed to analyse ${file.name}`, error)
      }

      processedFiles += 1
      setProgress((processedFiles / uploads.length) * 100)
      await new Promise((resolve) => setTimeout(resolve, 120))
    }

    const snapshot = buildStats(allResults, processedFiles, totalLines)
    setStats(snapshot)
    setResults(allResults)
    setIsScanning(false)
    setScanComplete(true)
    setCurrentFile("")

    if (fileInputRef.current) {
      fileInputRef.current.value = ""
    }
  }

  const startQuickScan = async () => {
    const demoSources = [
      {
        name: "api/routes/user.js",
        content: `app.post("/login", async (req, res) => {
  const query = "SELECT * FROM users WHERE email = '" + req.body.email + "'";
  const result = await db.query(query);
  res.json(result);
});
const token = Math.random().toString(36);
`,
      },
      {
        name: "services/payment.py",
        content: `import random
import hashlib

def build_signature(payload, secret="sk-demo-123"):
    if DEBUG == True:
        print("Debug mode enabled")
    token = secret + str(random.random())
    return hashlib.md5(token.encode()).hexdigest()
`,
      },
      {
        name: "legacy/worker.php",
        content: `<?php
$awsKey = "AKIAIOSFODNN7EXAMPLE";
$command = $_GET['cmd'];
exec($command);
?>
`,
      },
      {
        name: "frontend/dashboard.tsx",
        content: `const html = "<h1>" + userInput + "</h1>";
document.getElementById("target").innerHTML = html;
fetch("http://partner.example.com/api")
`,
      },
      {
        name: "controllers/proxy.js",
        content: `app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  const response = await fetch(target);
  res.json(await response.json());
});

app.get("/download", (req, res) => {
  const file = path.join(__dirname, "uploads", req.query.path);
  return res.sendFile(file);
});

app.use(cors({ origin: "*" }));
`,
      },
      {
        name: "services/client.py",
        content: `import requests

def forward_payment(url, payload):
    return requests.post(url, json=payload, verify=False)

def store_session(resp):
    response = make_response(resp)
    response.set_cookie("session", "abc123", secure=False)
    return response
`,
      },
    ]

    setIsScanning(true)
    setProgress(0)
    setScanComplete(false)
    setResults([])

    let aggregated: ScanResult[] = []
    let totalLines = 0

    for (let i = 0; i < demoSources.length; i += 1) {
      const source = demoSources[i]
      setCurrentFile(source.name)
      const { results: fileResults, totalLines: fileLines } = analyzeContent(source.name, source.content)
      aggregated = aggregated.concat(fileResults)
      totalLines += fileLines
      setProgress(((i + 1) / demoSources.length) * 100)
      await new Promise((resolve) => setTimeout(resolve, 200))
    }

    const snapshot = buildStats(aggregated, demoSources.length, totalLines)
    setStats(snapshot)
    setResults(aggregated)
    setIsScanning(false)
    setScanComplete(true)
    setCurrentFile("")
  }

  const filteredResults = selectedSeverity === "all" ? results : results.filter((result) => result.severity === selectedSeverity)

  const overviewCards = [
    {
      label: "Files scanned",
      value: stats.filesScanned,
      description: "Uploaded source files",
    },
    {
      label: "Lines processed",
      value: stats.totalLines,
      description: "Lines of code analysed",
    },
    {
      label: "Issues detected",
      value: stats.totalIssues,
      description: "Total findings across severities",
    },
  ]

  const severityBreakdown: Array<{ severity: Severity; value: number }> = [
    { severity: "critical", value: stats.critical },
    { severity: "high", value: stats.high },
    { severity: "medium", value: stats.medium },
    { severity: "low", value: stats.low },
  ]

  return (
    <>
      <Header />
      <main className="mx-auto max-w-7xl px-4 py-8">
        <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-8 text-center">
          <h1 className="mb-3 flex items-center justify-center gap-3 text-3xl font-semibold text-foreground">
            <Shield className="h-8 w-8 text-brand" />
            OneStop-CYworld Basic Scan
          </h1>
          <p className="text-muted-foreground">
            Upload individual files or entire project folders to run fast heuristic checks for high-signal vulnerability patterns across 30+ languages.
          </p>
        </motion.section>

        <div className="grid gap-6 lg:grid-cols-3">
          <motion.aside initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="space-y-6 lg:col-span-1">
            <TerminalBox title="Basic scan configuration">
              <div className="space-y-4">
                <div className="flex flex-col gap-3">
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    // @ts-ignore - webkitdirectory is a valid HTML attribute
                    webkitdirectory={folderMode ? "true" : undefined}
                    accept={folderMode ? undefined : ".py,.js,.jsx,.ts,.tsx,.php,.java,.cpp,.c,.h,.cs,.rb,.go,.rs,.swift,.json,.env,.yml,.yaml,.toml,.xml,.html,.css,.sql,.sh,.bat,.ps1,.dockerfile,.tf,.hcl"}
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <input
                        type="radio"
                        id="file-mode"
                        name="upload-mode"
                        checked={!folderMode}
                        onChange={() => setFolderMode(false)}
                        className="h-4 w-4 text-brand focus:ring-brand"
                      />
                      <label htmlFor="file-mode" className="text-sm text-foreground">Upload files</label>
                    </div>
                    <div className="flex items-center gap-2">
                      <input
                        type="radio"
                        id="folder-mode"
                        name="upload-mode"
                        checked={folderMode}
                        onChange={() => setFolderMode(true)}
                        className="h-4 w-4 text-brand focus:ring-brand"
                      />
                      <label htmlFor="folder-mode" className="text-sm text-foreground">Upload folder</label>
                    </div>
                  </div>

                  <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => fileInputRef.current?.click()}
                    disabled={isScanning}
                    className="flex items-center justify-center gap-2 rounded-lg border border-border bg-card px-4 py-2 font-medium text-foreground transition-colors hover:bg-card/80 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <Upload className="h-4 w-4" />
                    {folderMode ? "Select project folder" : "Select source files"}
                  </motion.button>

                  <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={startQuickScan}
                    disabled={isScanning}
                    className="flex items-center justify-center gap-2 rounded-lg bg-brand px-4 py-2 font-medium text-white transition-colors hover:bg-brand/90 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <Play className="h-4 w-4" />
                    Run demo scan
                  </motion.button>

                  {/* Secrets scan from GitHub URL */}
                  <GitHubSecretsScan />
                </div>

                <AnimatePresence>
                  {isScanning && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      className="space-y-2"
                    >
                      <ProgressBar value={progress} />
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Clock className="h-4 w-4 animate-spin" />
                        <span>Processing {currentFile || "files"}…</span>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </TerminalBox>

            {scanComplete && (
              <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
                <TerminalBox title="Basic scan metrics">
                  <div className="grid gap-4 sm:grid-cols-3">
                    {overviewCards.map((card) => (
                      <div key={card.label} className={baseCardClass}>
                        <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground/80">
                          {card.label}
                        </div>
                        <div className="mt-2 text-2xl font-semibold text-foreground">{formatNumber(card.value)}</div>
                        <div className="text-xs text-muted-foreground/80">{card.description}</div>
                      </div>
                    ))}
                  </div>

                  <div className="mt-4 grid gap-3 sm:grid-cols-2">
                    {severityBreakdown.map(({ severity, value }) => {
                      const Icon = severityIcons[severity]
                      const style = severityStyles[severity]
                      return (
                        <div key={severity} className={`${baseCardClass} ${style.accent}`}>
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium capitalize text-muted-foreground">{severity}</span>
                            <Icon className={`h-4 w-4 ${style.icon}`} />
                          </div>
                          <div className={`mt-2 text-xl font-semibold ${style.icon}`}>{formatNumber(value)}</div>
                          <div className="text-xs text-muted-foreground/80">Findings flagged</div>
                        </div>
                      )
                    })}
                  </div>
                </TerminalBox>
              </motion.div>
            )}
          </motion.aside>

          <motion.section initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-6 lg:col-span-2">
            <TerminalBox title="Basic scan findings">
              {!scanComplete && !isScanning && (
                <div className="flex flex-col items-center justify-center gap-3 py-16 text-center text-muted-foreground">
                  <ShieldCheck className="h-10 w-10 text-brand" />
                  <p className="text-sm">Upload individual files or entire project folders to surface baseline issues across injections, secrets, transport, and file handling. Supports 30+ languages and file types.</p>
                </div>
              )}

              {isScanning && (
                <div className="flex flex-col items-center justify-center gap-3 py-12 text-center text-muted-foreground">
                  <Clock className="h-10 w-10 animate-spin" />
                  <p className="text-sm">Scanning {currentFile || "files"}…</p>
                </div>
              )}

              {scanComplete && (
                <div className="space-y-5">
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => setSelectedSeverity("all")}
                      className={`rounded-full px-3 py-1 text-sm font-medium transition-colors ${
                        selectedSeverity === "all"
                          ? "bg-brand text-white"
                          : "bg-muted text-muted-foreground hover:bg-muted/80"
                      }`}
                    >
                      All ({formatNumber(results.length)})
                    </button>
                    {(["critical", "high", "medium", "low"] as Severity[]).map((severity) => {
                      const style = severityStyles[severity]
                      return (
                        <button
                          key={severity}
                          type="button"
                          onClick={() => setSelectedSeverity(severity)}
                          className={`rounded-full px-3 py-1 text-sm font-medium transition-colors ${
                            selectedSeverity === severity
                              ? style.button
                              : "bg-muted text-muted-foreground hover:bg-muted/80"
                          }`}
                        >
                          {severity.charAt(0).toUpperCase() + severity.slice(1)} ({formatNumber(stats[severity])})
                        </button>
                      )
                    })}
                  </div>

                  <div className="max-h-[30rem] space-y-3 overflow-y-auto pr-1">
                    <AnimatePresence>
                      {filteredResults.map((result) => {
                        const Icon = severityIcons[result.severity]
                        const style = severityStyles[result.severity]
                        return (
                          <motion.article
                            key={`${result.file}-${result.line}-${result.rule}`}
                            initial={{ opacity: 0, x: 16 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: -16 }}
                            transition={{ duration: 0.2 }}
                            className={`${baseCardClass} ${style.accent} space-y-4`}
                          >
                            <div className="flex flex-wrap items-start justify-between gap-3">
                              <div className="flex items-start gap-3">
                                <Icon className={`mt-0.5 h-5 w-5 ${style.icon}`} />
                                <div>
                                  <p className="text-sm font-semibold text-foreground">{result.type}</p>
                                  <p className="text-xs text-muted-foreground">
                                    Line {result.line} • {result.file}
                                  </p>
                                </div>
                              </div>
                              <span className={`rounded-full px-2 py-1 text-xs font-medium ${style.badge}`}>
                                {result.rule}
                              </span>
                            </div>

                            <p className="text-sm text-muted-foreground">{result.message}</p>

                            <div className="overflow-hidden rounded-lg border border-border bg-surface">
                              <div className="flex items-center justify-between gap-2 border-b border-border bg-surface/80 px-3 py-2 text-xs font-medium text-muted-foreground">
                                <div className="flex items-center gap-2">
                                  <FileCode className="h-4 w-4" />
                                  Code excerpt
                                </div>
                                <span>Line {result.line}</span>
                              </div>
                              <pre className="max-h-60 overflow-x-auto text-sm leading-relaxed">
                                {result.code.map((codeLine) => (
                                  <span
                                    key={`${result.file}-${codeLine.number}`}
                                    className={`flex gap-4 px-3 py-1 font-mono whitespace-pre ${
                                      codeLine.isHighlight ? "bg-brand/10 text-foreground" : "text-muted-foreground"
                                    }`}
                                  >
                                    <span className="w-12 text-right text-xs text-muted-foreground">
                                      {codeLine.number.toString().padStart(4, " ")}
                                    </span>
                                    <span>{codeLine.content || " "}</span>
                                  </span>
                                ))}
                              </pre>
                            </div>

                            <div className="rounded-lg border border-border/60 bg-surface/80 px-3 py-2 text-xs text-muted-foreground">
                              <div className="flex items-center gap-2 font-semibold text-foreground">
                                <FileText className="h-4 w-4" />
                                Remediation
                              </div>
                              <p className="mt-1 leading-relaxed">{result.remediation}</p>
                            </div>
                          </motion.article>
                        )
                      })}
                    </AnimatePresence>

                    {filteredResults.length === 0 && (
                      <div className="flex flex-col items-center justify-center gap-3 py-12 text-center text-muted-foreground">
                        <CheckCircle2 className="h-10 w-10 text-[#355952]" />
                        <p className="text-sm">No findings for the selected severity. Great job!</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </TerminalBox>
          </motion.section>
        </div>
      </main>
    </>
  )
}
