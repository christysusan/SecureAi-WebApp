"use client"

import { useEffect, useRef, useState } from "react"
import { AnimatePresence, motion } from "framer-motion"
import {
  AlertCircle,
  AlertOctagon,
  AlertTriangle,
  Brain,
  CheckCircle2,
  FileCode,
  Info,
  KeyRound,
  Lock,
  ShieldCheck,
  Upload,
} from "lucide-react"

import { Header } from "@/components/layout/header"
import { TerminalBox } from "@/components/layout/terminal-box"
import { ProgressBar } from "@/components/ui/progress-bar"

type Severity = "critical" | "high" | "medium" | "low"

interface StoredConfig {
  salt: string
  iv: string
  cipher: string
  provider: string
  confidence: number
  enableAI: boolean
  storedAt: string
}

interface CodeFrameLine {
  number: number
  content: string
  isHighlight: boolean
}

interface ScanResult {
  file: string
  line: number | null
  severity: Severity
  type: string
  message: string
  rule: string
  remediation: string
  code: CodeFrameLine[]
}

interface ScanStats {
  totalIssues: number
  critical: number
  high: number
  medium: number
  low: number
  totalLines: number
}

interface ApiVulnerability {
  id: string
  title: string
  severity: Severity
  line: number | null
  endLine: number | null
  rule: string
  summary: string
  remediation: string
  references: string[]
  codeExcerpt: string | null
}

interface AIAnalysisResponse {
  summary: string
  provider: string
  tokensUsed: number | null
  vulnerabilities: ApiVulnerability[]
}

const severityStyles: Record<Severity, { accent: string; badge: string; icon: string; button: string }> = {
  critical: {
    accent: "ring-1 ring-red-200",
    badge: "border border-[#E37769] bg-[#E37769]/15 text-[#355952]",
    icon: "text-[#E37769]",
    button: "bg-[#E37769] text-[#FAF6E7] hover:bg-[#E37769]/90",
  },
  high: {
    accent: "ring-1 ring-orange-200",
    badge: "border border-[#E37769]/70 bg-[#E37769]/10 text-[#355952]",
    icon: "text-[#E37769]",
    button: "bg-[#E37769] text-[#FAF6E7] hover:bg-[#E37769]/90",
  },
  medium: {
    accent: "ring-1 ring-amber-200",
    badge: "border border-[#355952]/30 bg-[#355952]/5 text-[#355952]",
    icon: "text-[#355952]",
    button: "bg-[#355952] text-[#FAF6E7] hover:bg-[#355952]/90",
  },
  low: {
    accent: "ring-1 ring-blue-200",
    badge: "border border-[#355952]/20 bg-[#355952]/5 text-[#355952]/80",
    icon: "text-[#355952]/70",
    button: "bg-[#355952]/70 text-[#FAF6E7] hover:bg-[#355952]/80",
  },
}

const severityIcons = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
} as const

const baseCardClass = "rounded-xl border border-border bg-card p-4 shadow-sm"

const base64ToUint8Array = (base64: string): Uint8Array => {
  const binary = atob(base64)
  const length = binary.length
  const bytes = new Uint8Array(length)
  for (let i = 0; i < length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

const bufferToString = (buffer: ArrayBuffer) => new TextDecoder().decode(buffer)

const normalizeCode = (code: string) => code.replace(/\r\n/g, "\n")

const createCodeFrame = (lines: string[], highlightIndex: number | null, radius = 3): CodeFrameLine[] => {
  if (lines.length === 0) {
    return []
  }

  const clampedIndex = highlightIndex != null ? Math.min(Math.max(highlightIndex, 0), lines.length - 1) : 0
  const start = Math.max(0, clampedIndex - radius)
  const end = Math.min(lines.length - 1, clampedIndex + radius)
  const highlightEnabled = highlightIndex != null

  const frame: CodeFrameLine[] = []
  for (let i = start; i <= end; i += 1) {
    frame.push({
      number: i + 1,
      content: lines[i]?.replace(/\t/g, "  ") ?? "",
      isHighlight: highlightEnabled && i === clampedIndex,
    })
  }

  return frame
}

const findSnippetStart = (lines: string[], snippet: string | null): number | null => {
  if (!snippet) return null
  const snippetLines = snippet
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)

  if (snippetLines.length === 0) return null

  for (let i = 0; i < lines.length; i += 1) {
    const matches = snippetLines.every((snippetLine, offset) => {
      const codeLine = lines[i + offset]
      if (codeLine === undefined) return false
      return codeLine.trim() === snippetLine
    })
    if (matches) return i
  }

  return null
}

const buildCodeFrameForVulnerability = (lines: string[], vulnerability: ApiVulnerability): CodeFrameLine[] => {
  const highlightIndex =
    vulnerability.line != null && Number.isFinite(vulnerability.line)
      ? Math.max(0, Math.min(lines.length - 1, Math.floor(vulnerability.line) - 1))
      : findSnippetStart(lines, vulnerability.codeExcerpt)

  const contextRadius = (() => {
    if (vulnerability.endLine != null && vulnerability.line != null) {
      return Math.max(3, Math.ceil(Math.abs(vulnerability.endLine - vulnerability.line)) + 2)
    }
    if (vulnerability.codeExcerpt) {
      const snippetSize = vulnerability.codeExcerpt.split(/\r?\n/).filter((line) => line.trim().length > 0).length
      return Math.max(3, Math.ceil(snippetSize / 2) + 1)
    }
    return 3
  })()

  return createCodeFrame(lines, highlightIndex, contextRadius)
}

const buildStats = (issues: ScanResult[], totalLines: number): ScanStats => ({
  totalIssues: issues.length,
  critical: issues.filter((issue) => issue.severity === "critical").length,
  high: issues.filter((issue) => issue.severity === "high").length,
  medium: issues.filter((issue) => issue.severity === "medium").length,
  low: issues.filter((issue) => issue.severity === "low").length,
  totalLines,
})

const formatNumber = (value: number) => value.toLocaleString()

export default function AIAssessPage() {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [configStatus, setConfigStatus] = useState<"loading" | "ready" | "missing">("loading")
  const [storedConfig, setStoredConfig] = useState<StoredConfig | null>(null)
  const [passphrase, setPassphrase] = useState("")
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileContent, setFileContent] = useState("")
  const [analysisResults, setAnalysisResults] = useState<ScanResult[]>([])
  const [analysisStats, setAnalysisStats] = useState<ScanStats | null>(null)
  const [analysisSummary, setAnalysisSummary] = useState<string>("")
  const [analysisProvider, setAnalysisProvider] = useState<string>("")
  const [tokensUsed, setTokensUsed] = useState<number | null>(null)
  const [statusMessage, setStatusMessage] = useState<{ type: "success" | "error"; message: string } | null>(null)
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all")
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [progress, setProgress] = useState(0)

  useEffect(() => {
    if (typeof window === "undefined") return
    try {
      const raw = sessionStorage.getItem("secure_ai_config")
      if (!raw) {
        setConfigStatus("missing")
        setStoredConfig(null)
        return
      }
      const parsed = JSON.parse(raw) as StoredConfig
      setStoredConfig(parsed)
      setConfigStatus(parsed.enableAI ? "ready" : "missing")
    } catch (error) {
      console.error("Failed to load config", error)
      setConfigStatus("missing")
      setStoredConfig(null)
    }
  }, [])

  const deriveEncryptionKey = async (secret: string, salt: ArrayBuffer) => {
    const encoder = new TextEncoder()
    const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "PBKDF2" }, false, ["deriveKey"])
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100_000,
        hash: "SHA-256",
      },
      keyMaterial,
      {
        name: "AES-GCM",
        length: 256,
      },
      false,
      ["decrypt"],
    )
  }

  const decryptApiKey = async (config: StoredConfig, secret: string) => {
    const salt = base64ToUint8Array(config.salt)
    const iv = base64ToUint8Array(config.iv)
    const cipher = base64ToUint8Array(config.cipher)
    const saltBuffer = salt.buffer.slice(0) as ArrayBuffer
  const ivBuffer = iv.buffer.slice(0) as ArrayBuffer
    const cipherBuffer = cipher.buffer.slice(0) as ArrayBuffer
    const cryptoKey = await deriveEncryptionKey(secret, saltBuffer)
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBuffer }, cryptoKey, cipherBuffer)
    return bufferToString(decrypted)
  }

  const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return
    const content = await file.text()
    setSelectedFile(file)
    setFileContent(content)
    setAnalysisResults([])
    setAnalysisStats(null)
    setAnalysisSummary("")
    setTokensUsed(null)
    setStatusMessage(null)
  }

  const summarizeFindings = (issues: ScanResult[], stats: ScanStats) => {
    if (issues.length === 0) {
      return "No vulnerabilities detected in the uploaded snippet."
    }
    const topSeverity = ["critical", "high", "medium", "low"].find((severity) => stats[severity as Severity] > 0) as Severity | undefined
    if (!topSeverity) return "Vulnerabilities detected. Review the list below."
    const headline = topSeverity === "critical" ? "Critical risk" : topSeverity === "high" ? "High risk" : "Moderate risk"
    return `${headline}: ${stats[topSeverity]} ${topSeverity} finding${stats[topSeverity] === 1 ? "" : "s"} out of ${stats.totalIssues} total issues.`
  }

  const performAnalysis = async () => {
    if (configStatus === "missing" || !storedConfig) {
      setStatusMessage({ type: "error", message: "No AI configuration found. Save encrypted credentials on the Config page first." })
      return
    }

    if (!selectedFile || !fileContent) {
      setStatusMessage({ type: "error", message: "Upload a code file before starting the assessment." })
      return
    }

    const trimmedPassphrase = passphrase.trim()
    if (trimmedPassphrase.length < 8) {
      setStatusMessage({ type: "error", message: "Enter the passphrase you used to encrypt the API key (minimum 8 characters)." })
      return
    }

    if (typeof window === "undefined" || !window.crypto?.subtle) {
      setStatusMessage({ type: "error", message: "Secure context required. Please run this in a modern browser over HTTPS." })
      return
    }

    try {
      setIsAnalyzing(true)
      setProgress(10)
      setStatusMessage(null)
      setSeverityFilter("all")

      const apiKey = await decryptApiKey(storedConfig, trimmedPassphrase)
      if (!apiKey || apiKey.length < 12) {
        throw new Error("The decrypted API key looks invalid. Double-check your configuration.")
      }

      setProgress(35)

      const requestBody = {
        apiKey,
        provider: storedConfig.provider,
        fileName: selectedFile.name,
        code: fileContent,
        confidence: storedConfig.confidence,
      }

      setProgress(55)

      const response = await fetch("/api/ai/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      })

      if (!response.ok) {
        const errorPayload = await response.json().catch(() => null)
        const message =
          (errorPayload && typeof errorPayload.message === "string" && errorPayload.message) ||
          `AI provider returned status ${response.status}.`
        throw new Error(message)
      }

      const payload = (await response.json()) as Partial<AIAnalysisResponse>
      const normalizedLines = normalizeCode(fileContent).split("\n")
      const vulnerabilities = Array.isArray(payload.vulnerabilities) ? payload.vulnerabilities : []
      const mappedResults: ScanResult[] = vulnerabilities.map((vulnerability) => {
        const references = Array.isArray(vulnerability.references)
          ? vulnerability.references.filter((ref) => typeof ref === "string" && ref.trim().length > 0).join("\n")
          : ""
        const remediationSegments = [vulnerability.remediation, references].filter(
          (segment): segment is string => typeof segment === "string" && segment.trim().length > 0,
        )
        const remediationText = remediationSegments.join("\n")

        return {
          file: selectedFile.name,
          line: vulnerability.line,
          severity: vulnerability.severity,
          type: vulnerability.title,
          message: vulnerability.summary,
          rule: vulnerability.rule,
          remediation: remediationText || "Review the AI guidance and apply secure coding best practices.",
          code: buildCodeFrameForVulnerability(normalizedLines, vulnerability),
        }
      })

      const stats = buildStats(mappedResults, normalizedLines.length)
      const summary = payload.summary && payload.summary.trim().length ? payload.summary : summarizeFindings(mappedResults, stats)

      setProgress(90)

  setAnalysisResults(mappedResults)
  setAnalysisStats(stats)
  setAnalysisSummary(summary)
  setAnalysisProvider(typeof payload.provider === "string" ? payload.provider : storedConfig.provider)
  setTokensUsed(typeof payload.tokensUsed === "number" ? payload.tokensUsed : null)
      setStatusMessage({
        type: "success",
        message:
          mappedResults.length === 0
            ? "Assessment complete. No vulnerabilities detected."
            : `Assessment complete. ${mappedResults.length} finding${mappedResults.length === 1 ? "" : "s"} detected by AI.`,
      })
      setProgress(100)
    } catch (error) {
      console.error("AI assessment failed", error)
      const fallbackMessage =
        error instanceof Error && error.message
          ? error.message
          : "Unable to run the assessment. Verify the passphrase, provider, and API quota, then try again."
      setStatusMessage({ type: "error", message: fallbackMessage })
      setAnalysisResults([])
      setAnalysisStats(null)
      setAnalysisSummary("")
      setAnalysisProvider("")
      setTokensUsed(null)
    } finally {
      setTimeout(() => setProgress(0), 1200)
      setIsAnalyzing(false)
    }
  }

  const filteredResults = severityFilter === "all" ? analysisResults : analysisResults.filter((result) => result.severity === severityFilter)

  return (
    <>
      <Header />
      <main className="mx-auto max-w-7xl px-4 py-8 text-foreground">
        <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-10 text-center">
          <h1 className="mb-3 flex items-center justify-center gap-3 text-3xl font-semibold">
            <Brain className="h-8 w-8 text-brand" />
            AI-Assisted Code Review
          </h1>
          <p className="text-muted-foreground">
            Unlock your encrypted API key, upload a code sample, and let OneStop-CYworld surface high-impact vulnerabilities with contextual fixes.
          </p>
        </motion.section>

        <div className="grid gap-6 lg:grid-cols-3">
          <motion.aside initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="space-y-6 lg:col-span-1">
            <TerminalBox title="Assessment setup">
              <div className="space-y-4 text-sm">
                {configStatus === "loading" && (
                  <div className="rounded-lg border border-border bg-card/60 px-3 py-2 text-muted-foreground">Loading configuration…</div>
                )}

                {configStatus === "missing" && (
                  <div className="space-y-3 rounded-lg border border-[#E37769] bg-[#E37769]/10 p-4 text-[#355952]">
                    <p className="font-medium">No encrypted API key found.</p>
                    <p className="text-xs text-[#355952]/80">
                      Head to the Config tab, enable AI analysis, and store your key with a passphrase before running assessments.
                    </p>
                  </div>
                )}

                {configStatus === "ready" && storedConfig && (
                  <div className="space-y-3">
                    <div className="rounded-lg border border-border bg-card/70 p-3">
                      <div className="flex items-center gap-2 text-sm font-medium">
                        <ShieldCheck className="h-4 w-4 text-brand" />
                        Encrypted AI profile unlocked for this session
                      </div>
                      <dl className="mt-3 grid gap-2 text-xs text-muted-foreground">
                        <div className="flex justify-between">
                          <dt>Provider</dt>
                          <dd className="capitalize">{storedConfig.provider}</dd>
                        </div>
                        <div className="flex justify-between">
                          <dt>Confidence threshold</dt>
                          <dd>{storedConfig.confidence.toFixed(1)}</dd>
                        </div>
                        <div className="flex justify-between">
                          <dt>Stored</dt>
                          <dd>{new Date(storedConfig.storedAt).toLocaleTimeString()}</dd>
                        </div>
                      </dl>
                    </div>

                    <div className="space-y-2">
                      <label className="block text-xs font-semibold uppercase tracking-wide text-muted-foreground">Upload code file</label>
                      <input ref={fileInputRef} type="file" accept=".py,.js,.jsx,.ts,.tsx,.php,.java,.cpp,.c,.h,.cs,.rb,.go,.rs,.swift,.json,.env,.yml,.yaml,.toml" className="hidden" onChange={handleFileSelect} />
                      <motion.button
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={() => fileInputRef.current?.click()}
                        disabled={isAnalyzing}
                        className="flex w-full items-center justify-center gap-2 rounded-lg border border-border bg-card px-4 py-2 font-medium transition-colors hover:bg-card/80 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        <Upload className="h-4 w-4" />
                        {selectedFile ? selectedFile.name : "Select source file"}
                      </motion.button>
                    </div>

                    <div className="space-y-2">
                      <label className="block text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                        Passphrase
                      </label>
                      <div className="relative">
                        <input
                          type="password"
                          placeholder="Passphrase used on the Config page"
                          value={passphrase}
                          onChange={(event) => setPassphrase(event.target.value)}
                          className="w-full rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground shadow-sm focus:outline-none focus:ring-2 focus:ring-brand"
                          disabled={isAnalyzing}
                        />
                        <KeyRound className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                      </div>
                    </div>

                    <motion.button
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      onClick={performAnalysis}
                      disabled={isAnalyzing || configStatus !== "ready"}
                      className="flex w-full items-center justify-center gap-2 rounded-lg bg-brand px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand/90 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      <Brain className="h-4 w-4" />
                      {isAnalyzing ? "Running assessment…" : "Run AI assessment"}
                    </motion.button>

                    <AnimatePresence>
                      {(isAnalyzing || progress > 0) && (
                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} className="space-y-2">
                          <ProgressBar value={progress} />
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <Lock className="h-4 w-4" />
                            <span>{isAnalyzing ? "Encrypted key unlocked. Contacting AI provider…" : "Ready"}</span>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>

                    {statusMessage && (
                      <div
                        className={`rounded-lg border px-3 py-2 text-xs ${
                          statusMessage.type === "success"
                            ? "border-[#355952] bg-[#355952]/10 text-[#355952]"
                            : "border-[#E37769] bg-[#E37769]/10 text-[#355952]"
                        }`}
                      >
                        {statusMessage.message}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </TerminalBox>
          </motion.aside>

          <motion.section initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-6 lg:col-span-2">
            <TerminalBox title="AI findings">
              {!analysisStats && !isAnalyzing && (
                <div className="flex flex-col items-center justify-center gap-3 py-16 text-center text-muted-foreground">
                  <ShieldCheck className="h-10 w-10 text-brand" />
                  <p className="text-sm">Upload a file and unlock your key to view AI-powered findings.</p>
                </div>
              )}

              {isAnalyzing && (
                <div className="flex flex-col items-center justify-center gap-3 py-16 text-center text-muted-foreground">
                  <Brain className="h-10 w-10 animate-bounce text-brand" />
                  <p className="text-sm">Assessing {selectedFile?.name ?? "code"}…</p>
                </div>
              )}

              {analysisStats && !isAnalyzing && (
                <div className="space-y-6 text-sm">
                  <div className="grid gap-4 sm:grid-cols-3">
                    <div className={`${baseCardClass} ring-1 ring-brand/20`}>
                      <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground/80">Summary</div>
                      <p className="mt-2 text-base font-semibold text-foreground">{analysisSummary}</p>
                      <div className="mt-3 text-xs text-muted-foreground/80">
                        Provider: <span className="capitalize">{analysisProvider || "—"}</span>
                      </div>
                      {tokensUsed && (
                        <div className="text-xs text-muted-foreground/80">Estimated tokens: {formatNumber(tokensUsed)}</div>
                      )}
                    </div>
                    <div className={baseCardClass}>
                      <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground/80">Total issues</div>
                      <div className="mt-2 text-2xl font-semibold text-foreground">{formatNumber(analysisStats.totalIssues)}</div>
                      <div className="text-xs text-muted-foreground/80">Across {formatNumber(analysisStats.totalLines)} lines analysed</div>
                    </div>
                    <div className={baseCardClass}>
                      <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground/80">Top severity</div>
                      <div className="mt-2 text-2xl font-semibold text-foreground">
                        {(["critical", "high", "medium", "low"] as Severity[]).find((severity) => analysisStats[severity] > 0) ?? "None"}
                      </div>
                      <div className="text-xs text-muted-foreground/80">Critical: {analysisStats.critical} • High: {analysisStats.high}</div>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => setSeverityFilter("all")}
                      className={`rounded-full px-3 py-1 text-xs font-semibold transition-colors ${
                        severityFilter === "all"
                          ? "bg-brand text-white"
                          : "bg-muted text-muted-foreground hover:bg-muted/80"
                      }`}
                    >
                      All ({formatNumber(analysisResults.length)})
                    </button>
                    {(["critical", "high", "medium", "low"] as Severity[]).map((severity) => {
                      const style = severityStyles[severity]
                      return (
                        <button
                          key={severity}
                          type="button"
                          onClick={() => setSeverityFilter(severity)}
                          className={`rounded-full px-3 py-1 text-xs font-semibold transition-colors ${
                            severityFilter === severity ? style.button : "bg-muted text-muted-foreground hover:bg-muted/80"
                          }`}
                        >
                          {severity.charAt(0).toUpperCase() + severity.slice(1)} ({formatNumber(analysisStats[severity])})
                        </button>
                      )
                    })}
                  </div>

                  <div className="max-h-[32rem] space-y-3 overflow-y-auto pr-1">
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
                                    {result.line != null ? `Line ${result.line}` : "Line unknown"} • {result.file}
                                  </p>
                                </div>
                              </div>
                              <span className={`rounded-full px-2 py-1 text-xs font-medium ${style.badge}`}>
                                {result.rule}
                              </span>
                            </div>

                            <p className="text-xs text-muted-foreground">{result.message}</p>

                            <div className="overflow-hidden rounded-lg border border-border bg-surface">
                              <div className="flex items-center justify-between gap-2 border-b border-border bg-surface/80 px-3 py-2 text-xs font-medium text-muted-foreground">
                                <div className="flex items-center gap-2">
                                  <FileCode className="h-4 w-4" />
                                  Code excerpt
                                </div>
                                <span>{result.line != null ? `Line ${result.line}` : "Line unknown"}</span>
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
                                <FileCode className="h-4 w-4" />
                                Remediation guidance
                              </div>
                              <p className="mt-1 leading-relaxed">{result.remediation}</p>
                            </div>
                          </motion.article>
                        )
                      })}
                    </AnimatePresence>

                    {filteredResults.length === 0 && (
                      <div className="flex flex-col items-center justify-center gap-3 py-16 text-center text-muted-foreground">
                        <CheckCircle2 className="h-10 w-10 text-[#355952]" />
                        <p className="text-sm">No findings for the selected severity. You&apos;re in great shape!</p>
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
