"use client"

import { FormEvent, useEffect, useState } from "react"
import { AnimatePresence, motion } from "framer-motion"
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  CloudUpload,
  FileCode,
  FileWarning,
  FolderInput,
  GitPullRequest,
  Loader2,
  Sparkle,
  Wand2,
} from "lucide-react"

import { BackgroundOrnaments } from "@/components/decor/background-ornaments"
import { Header } from "@/components/layout/header"
import { TerminalBox } from "@/components/layout/terminal-box"
import { cn } from "@/lib/utils"

type ManifestType = "requirements" | "package-json" | "go-mod" | "plaintext"
type Severity = "critical" | "high" | "medium" | "low" | "unknown"

type ScanState = "idle" | "scanning" | "done"
type AiState = "idle" | "loading" | "ready" | "error"

type StoredConfig = {
  salt: string
  iv: string
  cipher: string
  provider: string
  confidence: number
  enableAI: boolean
  storedAt: string
}

type DependencyScanResponse = {
  stats: {
    totalDependencies: number
    vulnerableDependencies: number
    totalVulnerabilities: number
    highestSeverity: Severity | null
  }
  dependencies: Array<{
    dependency: {
      name: string
      version: string
      ecosystem: string
      reference?: string
    }
    vulnerabilities: Array<{
      id: string
      summary: string
      details: string
      severity: Severity
      severityScore: number
      published: string | null
      modified: string | null
      aliases: string[]
      references: string[]
      affectedRanges: string[]
      fixedVersion: string | null
      confidence: string | null
    }>
    highestSeverity: Severity
    totalVulnerabilities: number
  }>
}

type ManifestOption = {
  value: ManifestType
  label: string
  helper: string
  placeholder: string
}

type NormalizedRecommendation = {
  id: string
  title: string
  severity: Severity
  rule: string
  summary: string
  remediation: string
  references: string[]
}

type AIRecommendationResponse = {
  summary: string
  provider: string
  tokensUsed: number | null
  vulnerabilities: NormalizedRecommendation[]
}

const manifestOptions: ManifestOption[] = [
  {
    value: "requirements",
    label: "Python requirements.txt",
    helper: "Supports pinned lines like requests==2.31.0 (comments ignored).",
    placeholder: "flask==2.3.3\nrequests==2.31.0",
  },
  {
    value: "package-json",
    label: "Node package.json",
    helper: "Reads dependencies/devDependencies with exact versions (no ^ or ~ ranges).",
    placeholder: `{
  "dependencies": {
    "express": "4.18.2",
    "next": "14.2.4"
  }
}`,
  },
  {
    value: "go-mod",
    label: "Go go.mod",
    helper: "Parses require blocks and single-line require statements.",
    placeholder: `module example.com/app

require (
  github.com/gin-gonic/gin v1.9.1
)`,
  },
  {
    value: "plaintext",
    label: "Plaintext list",
    helper: "Use lines like PyPI:django@4.2.5 or npm:react@18.3.1 (ecosystem:name@version).",
    placeholder: "PyPI:django@4.2.5\nnpm:react@18.3.1",
  },
]

const severityBadges: Record<Severity, string> = {
  critical: "border border-red-500/50 bg-red-500/10 text-red-600 dark:text-red-200",
  high: "border border-orange-500/50 bg-orange-500/10 text-orange-600 dark:text-orange-200",
  medium: "border border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-200",
  low: "border border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-200",
  unknown: "border border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-200",
}

const severityIcons: Record<Exclude<Severity, "unknown">, typeof AlertCircle> = {
  critical: AlertTriangle,
  high: AlertTriangle,
  medium: AlertCircle,
  low: CheckCircle2,
}

const flowStages = [
  {
    title: "Manifest ingestion",
    description: "Upload a manifest or paste dependencies. We safely parse pinned versions.",
    icon: FolderInput,
  },
  {
    title: "OSV lookups",
    description: "Each package queries OSV.dev for known CVEs via the free range API.",
    icon: CloudUpload,
  },
  {
    title: "Prioritized report",
    description: "Findings are ranked by severity with suggested fixed versions when available.",
    icon: FileWarning,
  },
  {
    title: "AI remediation",
    description: "Optionally draft PR-ready upgrade plans using your configured AI provider.",
    icon: Wand2,
  },
]

const base64ToUint8Array = (value: string): Uint8Array => {
  const binary = atob(value)
  const length = binary.length
  const bytes = new Uint8Array(length)
  for (let i = 0; i < length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

const bufferToString = (buffer: ArrayBuffer) => new TextDecoder().decode(buffer)

const detectManifestType = (fileName: string): ManifestType => {
  const lower = fileName.toLowerCase()
  if (lower.endsWith("requirements.txt")) return "requirements"
  if (lower === "package.json") return "package-json"
  if (lower === "go.mod") return "go-mod"
  return "plaintext"
}

export default function DependencyScannerPage() {
  const [manifestType, setManifestType] = useState<ManifestType>("requirements")
  const [inputMode, setInputMode] = useState<"upload" | "paste">("paste")
  const [fileName, setFileName] = useState<string>("")
  const [content, setContent] = useState<string>("")
  const [scanState, setScanState] = useState<ScanState>("idle")
  const [scanError, setScanError] = useState<string | null>(null)
  const [scanResult, setScanResult] = useState<DependencyScanResponse | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  const [configStatus, setConfigStatus] = useState<"loading" | "ready" | "missing">("loading")
  const [storedConfig, setStoredConfig] = useState<StoredConfig | null>(null)
  const [passphrase, setPassphrase] = useState("")
  const [aiState, setAiState] = useState<AiState>("idle")
  const [aiError, setAiError] = useState<string | null>(null)
  const [aiPlan, setAiPlan] = useState<AIRecommendationResponse | null>(null)

  useEffect(() => {
    if (typeof window === "undefined") return
    try {
      const raw = window.sessionStorage.getItem("secure_ai_config")
      if (!raw) {
        setConfigStatus("missing")
        setStoredConfig(null)
        return
      }
      const parsed = JSON.parse(raw) as StoredConfig
      if (!parsed.enableAI) {
        setConfigStatus("missing")
        setStoredConfig(parsed)
        return
      }
      setStoredConfig(parsed)
      setConfigStatus("ready")
    } catch (error) {
      console.error("Failed to load AI config", error)
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

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return
    const text = await file.text()
    const inferred = detectManifestType(file.name)
    setManifestType(inferred)
    setFileName(file.name)
    setContent(text)
    setInputMode("upload")
    setScanState("idle")
    setScanResult(null)
    setScanError(null)
    setAiPlan(null)
    setAiState("idle")
    setAiError(null)
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault()
    if (!content.trim()) {
      setScanError("Provide dependency content or upload a manifest file.")
      return
    }

    setIsSubmitting(true)
    setScanState("scanning")
    setScanError(null)
    setScanResult(null)
    setAiPlan(null)
    setAiState("idle")
    setAiError(null)

    try {
      const response = await fetch("/api/dependency-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ manifestType, content }),
      })

      if (!response.ok) {
        const payload = await response.json().catch(() => null)
        const message = (payload && typeof payload.message === "string" && payload.message) || "Dependency scan failed."
        throw new Error(message)
      }

      const payload = (await response.json()) as DependencyScanResponse
      setScanResult(payload)
      setScanState("done")
    } catch (error) {
      console.error("Dependency scan failed", error)
      setScanError(error instanceof Error ? error.message : "Unable to complete the scan.")
      setScanState("idle")
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleGenerateAiPlan = async () => {
    if (!scanResult) {
      setAiError("Run a vulnerability scan before generating AI suggestions.")
      setAiState("error")
      return
    }
    if (scanResult.stats.totalVulnerabilities === 0) {
      setAiError("No vulnerabilities detected. AI remediation is not required.")
      setAiState("error")
      return
    }
    if (configStatus !== "ready" || !storedConfig) {
      setAiError("Configure and unlock an AI provider on the Config page first.")
      setAiState("error")
      return
    }
    const trimmedPassphrase = passphrase.trim()
    if (trimmedPassphrase.length < 8) {
      setAiError("Enter the passphrase you used to encrypt the API key (minimum 8 characters).")
      setAiState("error")
      return
    }
    if (typeof window === "undefined" || !window.crypto?.subtle) {
      setAiError("Secure context required. Please use a modern browser over HTTPS.")
      setAiState("error")
      return
    }

    try {
      setAiState("loading")
      setAiError(null)

      const apiKey = await decryptApiKey(storedConfig, trimmedPassphrase)
      if (!apiKey || apiKey.length < 12) {
        throw new Error("The decrypted API key looks invalid. Double-check your configuration.")
      }

      const aiPayload = {
        generatedAt: new Date().toISOString(),
        stats: scanResult.stats,
        dependencies: scanResult.dependencies.map((entry) => ({
          name: entry.dependency.name,
          version: entry.dependency.version,
          ecosystem: entry.dependency.ecosystem,
          vulnerabilities: entry.vulnerabilities.map((vuln) => ({
            id: vuln.id,
            summary: vuln.summary,
            severity: vuln.severity,
            fixedVersion: vuln.fixedVersion,
            references: vuln.references,
            aliases: vuln.aliases,
          })),
        })),
      }

      const response = await fetch("/api/ai/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          apiKey,
          provider: storedConfig.provider,
          fileName: "dependencies-report.json",
          code: JSON.stringify(aiPayload, null, 2),
          confidence: storedConfig.confidence,
          mode: "dependencies",
        }),
      })

      if (!response.ok) {
        const payload = await response.json().catch(() => null)
        const message = (payload && typeof payload.message === "string" && payload.message) || "AI provider returned an error."
        throw new Error(message)
      }

      const payload = (await response.json()) as AIRecommendationResponse
      setAiPlan(payload)
      setAiState("ready")
    } catch (error) {
      console.error("AI remediation failed", error)
      setAiError(error instanceof Error ? error.message : "Unable to generate AI remediation suggestions.")
      setAiState("error")
    }
  }

  const highestSeverity = scanResult?.stats.highestSeverity ?? null
  const summaryHeadline = (() => {
    if (!scanResult) return "Run a scan to reveal dependency risks."
    if (scanResult.stats.totalVulnerabilities === 0) return "All clear — no known vulnerabilities detected."
    if (highestSeverity === "critical") return "Critical vulnerabilities detected"
    if (highestSeverity === "high") return "High severity vulnerabilities detected"
    if (highestSeverity === "medium") return "Moderate vulnerabilities detected"
    return "Low severity issues detected"
  })()

  const summaryTone = (() => {
    if (!scanResult || scanResult.stats.totalVulnerabilities === 0) return "text-emerald-500"
    if (!highestSeverity || highestSeverity === "unknown") return "text-foreground"
    if (highestSeverity === "critical") return "text-red-500"
    if (highestSeverity === "high") return "text-orange-500"
    if (highestSeverity === "medium") return "text-amber-500"
    return "text-blue-500"
  })()

  return (
    <>
      <Header />
      <main className="relative mx-auto max-w-6xl px-4 py-8">
        <BackgroundOrnaments />

        <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-10 space-y-4">
          <div>
            <h1 className="text-4xl font-semibold text-foreground">Dependency Vulnerability Scanner</h1>
            <p className="mt-3 max-w-2xl text-base text-foreground/80">
              Upload a manifest or paste your dependency list to query the OSV.dev vulnerability database. We prioritize
              known CVEs, highlight available fixes, and can draft AI-generated remediation plans and PR copy.
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            {flowStages.map((stage, index) => {
              const Icon = stage.icon
              return (
                <motion.div
                  key={stage.title}
                  initial={{ opacity: 0, y: 24 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.08 }}
                  className="flex items-start gap-3 rounded-xl border border-border bg-card/80 p-4 shadow-sm backdrop-blur"
                >
                  <div className="mt-1 flex h-9 w-9 items-center justify-center rounded-full bg-brand/10 text-brand">
                    <Icon className="h-5 w-5" aria-hidden="true" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-foreground">{stage.title}</h3>
                    <p className="mt-1 text-xs leading-relaxed text-foreground/75">{stage.description}</p>
                  </div>
                </motion.div>
              )
            })}
          </div>
        </motion.section>

        <div className="grid gap-6 lg:grid-cols-[1.25fr_1fr]">
          <motion.section initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.12 }}>
            <TerminalBox title="Upload or paste dependencies" className="space-y-6">
              <form onSubmit={handleSubmit} className="space-y-5">
                <div>
                  <span className="text-sm font-medium text-foreground">Manifest type</span>
                  <div className="mt-2 grid gap-2 sm:grid-cols-2">
                    {manifestOptions.map((option) => (
                      <button
                        type="button"
                        key={option.value}
                        onClick={() => {
                          setManifestType(option.value)
                          setInputMode("paste")
                          setFileName("")
                        }}
                        className={cn(
                          "flex flex-col items-start gap-2 rounded-lg border border-border bg-surface p-3 text-left transition",
                          manifestType === option.value ? "border-brand ring-1 ring-brand/40" : "hover:border-brand/60",
                        )}
                      >
                        <span className="text-sm font-semibold text-foreground">{option.label}</span>
                        <span className="text-xs text-foreground/70">{option.helper}</span>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex flex-col gap-3">
                  <div className="flex items-center justify-between text-xs text-foreground/70">
                    <span>{inputMode === "upload" ? fileName || "No file selected" : "Paste dependencies"}</span>
                    <label className="inline-flex cursor-pointer items-center gap-2 text-brand hover:text-brand/80">
                      <input type="file" accept=".txt,.json,.mod,.lock" className="hidden" onChange={handleFileUpload} />
                      <CloudUpload className="h-4 w-4" aria-hidden="true" />
                      <span className="text-xs font-medium">Upload manifest</span>
                    </label>
                  </div>
                  <textarea
                    value={content}
                    onChange={(event) => {
                      setContent(event.target.value)
                      setInputMode("paste")
                    }}
                    rows={manifestType === "package-json" ? 12 : 8}
                    className="h-full min-h-[200px] w-full rounded-lg border border-border bg-surface px-3 py-3 font-mono text-sm text-foreground shadow-sm focus-visible:border-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
                    placeholder={manifestOptions.find((option) => option.value === manifestType)?.placeholder}
                  />
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="text-xs text-foreground/70">
                    Supports up to 50 pinned dependencies per scan. Ranges like ^ or ~ are ignored for accuracy.
                  </p>
                  <button
                    type="submit"
                    className="inline-flex items-center gap-2 rounded-lg bg-brand px-4 py-2 text-sm font-semibold text-white shadow transition hover:bg-brand/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
                    disabled={isSubmitting}
                  >
                    {isSubmitting ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Scanning dependencies...
                      </>
                    ) : (
                      <>
                        Run dependency scan
                        <FileCode className="h-4 w-4" aria-hidden="true" />
                      </>
                    )}
                  </button>
                </div>

                {scanError && <p className="text-sm text-destructive">{scanError}</p>}
              </form>
            </TerminalBox>

            <TerminalBox title="Scan summary" className="mt-6 space-y-4">
              <div className="flex items-start gap-3">
                <div className={cn("rounded-full bg-muted p-2", summaryTone)}>
                  {scanResult && scanResult.stats.totalVulnerabilities > 0 ? (
                    <FileWarning className="h-5 w-5" aria-hidden="true" />
                  ) : (
                    <CheckCircle2 className="h-5 w-5" aria-hidden="true" />
                  )}
                </div>
                <div>
                  <h3 className="text-base font-semibold text-foreground">{summaryHeadline}</h3>
                  <p className="mt-1 text-sm text-foreground/80">
                    {scanResult
                      ? scanResult.stats.totalVulnerabilities === 0
                        ? "OSV.dev reported no known CVEs for the parsed dependencies."
                        : (() => {
                            const vulnCount = scanResult.stats.totalVulnerabilities
                            const depCount = scanResult.stats.vulnerableDependencies
                            const vulnLabel = vulnCount === 1 ? "vulnerability" : "vulnerabilities"
                            const depLabel = depCount === 1 ? "package" : "packages"
                            return `${vulnCount} ${vulnLabel} across ${depCount} ${depLabel}.`
                          })()
                      : "Once scanned, you will see total CVEs and impacted dependencies."}
                  </p>
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                <div className="rounded-lg border border-border bg-surface/60 p-3">
                  <span className="text-xs uppercase tracking-wide text-foreground/65">Dependencies</span>
                  <p className="mt-1 text-2xl font-semibold text-foreground">
                    {scanResult ? scanResult.stats.totalDependencies : "—"}
                  </p>
                </div>
                <div className="rounded-lg border border-border bg-surface/60 p-3">
                  <span className="text-xs uppercase tracking-wide text-foreground/65">Vulnerable packages</span>
                  <p className="mt-1 text-2xl font-semibold text-foreground">
                    {scanResult ? scanResult.stats.vulnerableDependencies : "—"}
                  </p>
                </div>
                <div className="rounded-lg border border-border bg-surface/60 p-3">
                  <span className="text-xs uppercase tracking-wide text-foreground/65">Total CVEs</span>
                  <p className="mt-1 text-2xl font-semibold text-foreground">
                    {scanResult ? scanResult.stats.totalVulnerabilities : "—"}
                  </p>
                </div>
              </div>
            </TerminalBox>
          </motion.section>

          <motion.section initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.18 }} className="space-y-6">
            <TerminalBox title="OSV findings" className="max-h-[640px] overflow-hidden">
              <div className="max-h-[560px] space-y-4 overflow-y-auto pr-1">
                {!scanResult && scanState !== "scanning" && (
                  <div className="rounded-lg border border-dashed border-border bg-muted/20 p-6 text-center">
                    <p className="text-sm text-foreground/75">
                      Run a scan to populate OSV results. We will list each vulnerable dependency with severity, CVE IDs,
                      and available fixes.
                    </p>
                  </div>
                )}

                {scanState === "scanning" && (
                  <div className="flex items-center gap-3 rounded-lg border border-border bg-muted/30 p-4 text-sm text-foreground/75">
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Querying OSV.dev for vulnerabilities...
                  </div>
                )}

                {scanResult &&
                  scanResult.dependencies.map((entry) => {
                    const badgeClass = severityBadges[entry.highestSeverity] ?? severityBadges.unknown
                    const hasVulns = entry.vulnerabilities.length > 0
                    return (
                      <motion.div
                        key={`${entry.dependency.ecosystem}:${entry.dependency.name}`}
                        initial={{ opacity: 0, y: 16 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="rounded-xl border border-border bg-card/90 p-4 shadow-sm"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-semibold text-foreground">
                                {entry.dependency.name}
                                <span className="ml-2 text-xs text-foreground/60">{entry.dependency.version}</span>
                              </span>
                              <span className="text-[10px] uppercase tracking-wide text-foreground/65">{entry.dependency.ecosystem}</span>
                            </div>
                            {entry.dependency.reference && (
                              <p className="text-xs text-foreground/70">{entry.dependency.reference}</p>
                            )}
                          </div>
                          <span className={cn("inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium", badgeClass)}>
                            {hasVulns ? `${entry.totalVulnerabilities} issue${entry.totalVulnerabilities === 1 ? "" : "s"}` : "No CVEs"}
                          </span>
                        </div>

                        <AnimatePresence>
                          {hasVulns && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: "auto" }}
                              exit={{ opacity: 0, height: 0 }}
                              transition={{ duration: 0.25 }}
                              className="mt-4 space-y-3"
                            >
                              {entry.vulnerabilities.map((vuln) => {
                                const Icon = severityIcons[(vuln.severity === "unknown" ? "medium" : vuln.severity) as Exclude<Severity, "unknown">]
                                return (
                                  <div
                                    key={vuln.id}
                                    className="rounded-lg border border-border bg-surface/70 p-4 text-sm text-foreground/80"
                                  >
                                    <div className="flex flex-wrap items-center gap-2">
                                      <span className={cn("inline-flex items-center gap-2 rounded-full px-2 py-1 text-[11px] font-semibold", severityBadges[vuln.severity])}>
                                        <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                                        {vuln.severity.toUpperCase()}
                                      </span>
                                      <span className="font-mono text-xs text-foreground/70">{vuln.id}</span>
                                      {vuln.aliases.length > 0 && (
                                        <span className="font-mono text-[10px] text-foreground/70">Aliases: {vuln.aliases.join(", ")}</span>
                                      )}
                                    </div>
                                    <p className="mt-2 font-semibold text-foreground">{vuln.summary}</p>
                                    {vuln.details && (
                                      <p className="mt-1 text-xs leading-relaxed text-foreground/70">
                                        {vuln.details.slice(0, 280)}{vuln.details.length > 280 ? "…" : ""}
                                      </p>
                                    )}
                                    <div className="mt-3 grid gap-2 text-xs text-foreground/75 sm:grid-cols-2">
                                      <div>
                                        <span className="font-medium text-foreground">Published:</span> {vuln.published ?? "—"}
                                      </div>
                                      <div>
                                        <span className="font-medium text-foreground">Modified:</span> {vuln.modified ?? "—"}
                                      </div>
                                      <div>
                                        <span className="font-medium text-foreground">Fixed in:</span> {vuln.fixedVersion ?? "No fix reported"}
                                      </div>
                                      {vuln.affectedRanges.length > 0 && (
                                        <div>
                                          <span className="font-medium text-foreground">Ranges:</span> {vuln.affectedRanges.join("; ")}
                                        </div>
                                      )}
                                    </div>
                                    {vuln.references.length > 0 && (
                                      <div className="mt-3 flex flex-wrap gap-2">
                                        {vuln.references.slice(0, 3).map((ref) => (
                                          <a
                                            key={ref}
                                            href={ref}
                                            target="_blank"
                                            rel="noreferrer"
                                            className="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-2 py-1 text-[11px] text-foreground/70 transition hover:border-brand hover:text-brand"
                                          >
                                            <GitPullRequest className="h-3 w-3" aria-hidden="true" />
                                            Reference
                                          </a>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                )
                              })}
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </motion.div>
                    )
                  })}
              </div>
            </TerminalBox>

            <TerminalBox title="AI remediation (optional)" className="space-y-4">
              <p className="text-sm text-foreground/80">
                Unlock an AI provider on the Config page, then decrypt it here to draft upgrade guidance, recommended
                versions, and PR-ready messaging based on the detected vulnerabilities.
              </p>

              <div className="space-y-3 rounded-lg border border-border bg-surface/70 p-4">
                <label className="flex flex-col gap-2 text-sm">
                  <span className="font-medium text-foreground">Encrypted API passphrase</span>
                  <input
                    type="password"
                    value={passphrase}
                    onChange={(event) => setPassphrase(event.target.value)}
                    placeholder="Enter passphrase to unlock provider"
                    className="w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-foreground focus-visible:border-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
                  />
                </label>
                <button
                  type="button"
                  onClick={handleGenerateAiPlan}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow transition hover:bg-indigo-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400"
                  disabled={aiState === "loading"}
                >
                  {aiState === "loading" ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                      Contacting AI provider...
                    </>
                  ) : (
                    <>
                      Generate remediation playbook
                      <Sparkle className="h-4 w-4" aria-hidden="true" />
                    </>
                  )}
                </button>
                {aiError && <p className="text-sm text-destructive">{aiError}</p>}
                {configStatus === "missing" && (
                  <p className="text-xs text-foreground/70">
                    Tip: Store encrypted API keys and select a provider on the Config page to enable AI suggestions.
                  </p>
                )}
              </div>

              {aiState === "ready" && aiPlan && (
                <div className="space-y-3 rounded-lg border border-brand/40 bg-brand/5 p-4">
                  <div className="flex items-center gap-2 text-sm text-brand">
                    <Wand2 className="h-4 w-4" aria-hidden="true" />
                    <span>
                      {aiPlan.provider ? `AI suggestions powered by ${aiPlan.provider}` : "AI remediation summary"}
                      {typeof aiPlan.tokensUsed === "number" && aiPlan.tokensUsed > 0 ? ` · ${aiPlan.tokensUsed} tokens` : ""}
                    </span>
                  </div>
                  <p className="text-sm text-foreground/85">{aiPlan.summary}</p>
                  <div className="space-y-3">
                    {aiPlan.vulnerabilities.map((item) => (
                      <div key={item.id} className="rounded-lg border border-border bg-surface/80 p-3 text-sm text-foreground/80">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-semibold text-foreground">{item.title}</span>
                          <span className="text-[11px] uppercase tracking-wide text-foreground/65">{item.severity}</span>
                        </div>
                        <p className="mt-1 text-xs leading-relaxed text-foreground/75">{item.summary}</p>
                        <p className="mt-2 whitespace-pre-line text-xs text-foreground/80">{item.remediation}</p>
                        {item.references.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-2">
                            {item.references.map((ref) => (
                              <a
                                key={ref}
                                href={ref}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-2 py-1 text-[10px] text-foreground/70 transition hover:border-brand hover:text-brand"
                              >
                                <GitPullRequest className="h-3 w-3" aria-hidden="true" />
                                Resource
                              </a>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </TerminalBox>
          </motion.section>
        </div>

        <motion.section initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.24 }} className="mt-10">
          <TerminalBox title="Best practices" className="grid gap-4 md:grid-cols-3">
            <div className="rounded-lg border border-border bg-surface/60 p-4 text-sm text-foreground/80">
              <h3 className="text-sm font-semibold text-foreground">Pin versions & monitor</h3>
              <p className="mt-1 text-xs leading-relaxed text-foreground/75">
                Keep manifests deterministic with exact versions. Automate nightly OSV scans or CI gates to block risky upgrades.
              </p>
            </div>
            <div className="rounded-lg border border-border bg-surface/60 p-4 text-sm text-foreground/80">
              <h3 className="text-sm font-semibold text-foreground">Triage by severity</h3>
              <p className="mt-1 text-xs leading-relaxed text-foreground/75">
                Patch critical/high CVEs immediately. Medium issues can bundle into maintenance releases, while low-risk
                advisories can follow normal upgrade cadences.
              </p>
            </div>
            <div className="rounded-lg border border-border bg-surface/60 p-4 text-sm text-foreground/80">
              <h3 className="text-sm font-semibold text-foreground">Document remediation</h3>
              <p className="mt-1 text-xs leading-relaxed text-foreground/75">
                Record resolved CVEs, linked PRs, and upgrade rationales for auditors. AI-generated PR copy helps keep teams aligned.
              </p>
            </div>
          </TerminalBox>
        </motion.section>
      </main>
    </>
  )
}
