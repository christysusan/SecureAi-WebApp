"use client"

import { FormEvent, useState } from "react"
import { motion } from "framer-motion"
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  CloudUpload,
  FileCode,
  Loader2,
} from "lucide-react"

import { BackgroundOrnaments } from "@/components/decor/background-ornaments"
import { Header } from "@/components/layout/header"
import { TerminalBox } from "@/components/layout/terminal-box"
import { cn } from "@/lib/utils"

type ManifestType = "requirements" | "package-json" | "go-mod" | "plaintext"
type Severity = "critical" | "high" | "medium" | "low" | "unknown"

type ScanState = "idle" | "scanning" | "done"

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
    }
    vulnerabilities: Array<{
      id: string
      summary: string
      severity: Severity
      fixedVersion: string | null
    }>
    highestSeverity: Severity
    totalVulnerabilities: number
  }>
}

const manifestOptions = [
  { value: "requirements" as ManifestType, label: "Python requirements.txt", placeholder: "django==4.1.0\nrequests==2.28.1" },
  { value: "package-json" as ManifestType, label: "Node.js package.json", placeholder: '"dependencies": {\n  "express": "4.18.0",\n  "lodash": "4.17.21"\n}' },
  { value: "go-mod" as ManifestType, label: "Go go.mod", placeholder: "require (\n\tgithub.com/gin-gonic/gin v1.8.1\n\tgorm.io/gorm v1.23.8\n)" },
]

const severityBadges: Record<Severity, string> = {
  critical: "border border-[#E37769] bg-[#E37769]/15 text-[#355952]",
  high: "border border-[#E37769]/70 bg-[#E37769]/10 text-[#355952]",
  medium: "border border-[#355952]/40 bg-[#355952]/10 text-[#355952]",
  low: "border border-[#355952]/30 bg-[#355952]/5 text-[#355952]/80",
  unknown: "border border-[#355952]/20 bg-[#355952]/5 text-[#355952]/60",
}

const severityIcons: Record<Exclude<Severity, "unknown">, typeof AlertCircle> = {
  critical: AlertTriangle,
  high: AlertTriangle,
  medium: AlertCircle,
  low: CheckCircle2,
}

export default function DependencyScannerPage() {
  const [manifestType, setManifestType] = useState<ManifestType>("requirements")
  const [content, setContent] = useState<string>("")
  const [scanState, setScanState] = useState<ScanState>("idle")
  const [scanResult, setScanResult] = useState<DependencyScanResponse | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (e) => {
      const text = e.target?.result as string
      setContent(text)
    }
    reader.readAsText(file)
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault()
    if (!content.trim()) return

    setIsSubmitting(true)
    setScanState("scanning")

    try {
      const response = await fetch("/api/dependency-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // body: JSON.stringify({ type: manifestType, content }),
        body: JSON.stringify({ manifestType, content }),
      })

      if (!response.ok) throw new Error("Scan failed")

      const data = await response.json()
      setScanResult(data)
      setScanState("done")
    } catch (error) {
      console.error("Scan error:", error)
      setScanState("idle")
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <>
      <Header />
      <main className="relative mx-auto max-w-6xl px-4 py-8">
        <BackgroundOrnaments />

        <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-10">
          <h1 className="text-4xl font-semibold text-foreground">Dependency Scanner</h1>
          <p className="mt-3 max-w-2xl text-base text-foreground/80">
            Upload your dependency manifest to check for known vulnerabilities via OSV.dev database.
          </p>
          
          <div className="mt-6 grid gap-4 md:grid-cols-3">
            <div className="flex items-start gap-3 rounded-lg border border-border bg-card/80 p-4">
              <div className="mt-1 flex h-8 w-8 items-center justify-center rounded-full bg-[#355952]/10 text-[#355952]">
                <CloudUpload className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-foreground">Upload Manifest</h3>
                <p className="mt-1 text-xs text-foreground/75">Paste or upload your dependency file</p>
              </div>
            </div>
            <div className="flex items-start gap-3 rounded-lg border border-border bg-card/80 p-4">
              <div className="mt-1 flex h-8 w-8 items-center justify-center rounded-full bg-[#355952]/10 text-[#355952]">
                <AlertCircle className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-foreground">OSV Lookup</h3>
                <p className="mt-1 text-xs text-foreground/75">Query known CVEs and vulnerabilities</p>
              </div>
            </div>
            <div className="flex items-start gap-3 rounded-lg border border-border bg-card/80 p-4">
              <div className="mt-1 flex h-8 w-8 items-center justify-center rounded-full bg-[#E37769]/10 text-[#E37769]">
                <FileCode className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-foreground">View Results</h3>
                <p className="mt-1 text-xs text-foreground/75">See vulnerabilities and fix recommendations</p>
              </div>
            </div>
          </div>
        </motion.section>

        <div className="grid gap-6 lg:grid-cols-2">
          <motion.section initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}>
            <TerminalBox title="Input">
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="text-sm font-medium text-foreground">Manifest Type</label>
                  <div className="mt-2 grid gap-2 sm:grid-cols-3">
                    {manifestOptions.map((option) => (
                      <button
                        type="button"
                        key={option.value}
                        onClick={() => setManifestType(option.value)}
                        className={cn(
                          "rounded-lg border border-border bg-surface p-3 text-left text-sm transition",
                          manifestType === option.value ? "border-[#355952] ring-1 ring-[#355952]/40" : "hover:border-[#355952]/60",
                        )}
                      >
                        {option.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-sm font-medium text-foreground">Dependencies</label>
                    <label className="inline-flex cursor-pointer items-center gap-2 text-[#355952] hover:text-[#355952]/80">
                      <input type="file" accept=".txt,.json,.mod" className="hidden" onChange={handleFileUpload} />
                      <CloudUpload className="h-4 w-4" />
                      <span className="text-xs font-medium">Upload file</span>
                    </label>
                  </div>
                  <textarea
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                    rows={8}
                    className="w-full rounded-lg border border-border bg-surface px-3 py-3 font-mono text-sm text-foreground focus-visible:border-[#355952] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#355952]"
                    placeholder={manifestOptions.find(option => option.value === manifestType)?.placeholder}
                  />
                </div>

                <button
                  type="submit"
                  className="w-full rounded-lg bg-[#355952] px-4 py-2 text-sm font-semibold text-[#FAF6E7] transition hover:bg-[#355952]/90"
                  disabled={isSubmitting || !content.trim()}
                >
                  {isSubmitting ? (
                    <>
                      <Loader2 className="inline h-4 w-4 animate-spin mr-2" />
                      Scanning...
                    </>
                  ) : (
                    "Scan Dependencies"
                  )}
                </button>
              </form>
            </TerminalBox>
          </motion.section>

          <motion.section initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
            <TerminalBox title="Results">
              <div className="space-y-4">
                {scanState === "idle" && !scanResult && (
                  <div className="rounded-lg border border-dashed border-border bg-muted/20 p-6 text-center">
                    <p className="text-sm text-foreground/75">Run a scan to see vulnerability results</p>
                  </div>
                )}

                {scanState === "scanning" && (
                  <div className="flex items-center gap-3 rounded-lg border border-border bg-muted/30 p-4">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span className="text-sm text-foreground/75">Checking vulnerabilities...</span>
                  </div>
                )}

                {scanResult && (
                  <>
                    <div className="grid gap-3 sm:grid-cols-3">
                      <div className="rounded-lg border border-border bg-surface/60 p-3">
                        <span className="text-xs uppercase tracking-wide text-foreground/65">Dependencies</span>
                        <p className="mt-1 text-xl font-semibold text-foreground">{scanResult.stats.totalDependencies}</p>
                      </div>
                      <div className="rounded-lg border border-border bg-surface/60 p-3">
                        <span className="text-xs uppercase tracking-wide text-foreground/65">Vulnerable</span>
                        <p className="mt-1 text-xl font-semibold text-foreground">{scanResult.stats.vulnerableDependencies}</p>
                      </div>
                      <div className="rounded-lg border border-border bg-surface/60 p-3">
                        <span className="text-xs uppercase tracking-wide text-foreground/65">CVEs</span>
                        <p className="mt-1 text-xl font-semibold text-foreground">{scanResult.stats.totalVulnerabilities}</p>
                      </div>
                    </div>

                    <div className="max-h-96 space-y-3 overflow-y-auto">
                      {scanResult.dependencies
                        .filter(dep => dep.vulnerabilities.length > 0)
                        .map((dep) => (
                          <div key={`${dep.dependency.name}-${dep.dependency.version}`} className="rounded-lg border border-border bg-card/90 p-4">
                            <div className="flex items-center justify-between mb-3">
                              <div>
                                <span className="font-semibold text-foreground">{dep.dependency.name}</span>
                                <span className="ml-2 text-xs text-foreground/60">{dep.dependency.version}</span>
                              </div>
                              <span className={cn("rounded-full px-2 py-1 text-xs font-medium", severityBadges[dep.highestSeverity])}>
                                {dep.totalVulnerabilities} issue{dep.totalVulnerabilities === 1 ? "" : "s"}
                              </span>
                            </div>
                            
                            <div className="space-y-2">
                              {dep.vulnerabilities.slice(0, 2).map((vuln) => {
                                const Icon = severityIcons[(vuln.severity === "unknown" ? "medium" : vuln.severity) as Exclude<Severity, "unknown">]
                                return (
                                  <div key={vuln.id} className="rounded border border-border bg-surface/70 p-3 text-sm">
                                    <div className="flex items-center gap-2 mb-2">
                                      <Icon className="h-4 w-4 text-[#E37769]" />
                                      <span className="font-mono text-xs">{vuln.id}</span>
                                      <span className={cn("rounded px-1.5 py-0.5 text-xs", severityBadges[vuln.severity])}>
                                        {vuln.severity}
                                      </span>
                                    </div>
                                    <p className="text-foreground/80">{vuln.summary}</p>
                                    {vuln.fixedVersion && (
                                      <p className="mt-1 text-xs text-[#355952]">Fixed in: {vuln.fixedVersion}</p>
                                    )}
                                  </div>
                                )
                              })}
                              {dep.vulnerabilities.length > 2 && (
                                <p className="text-xs text-foreground/60">
                                  +{dep.vulnerabilities.length - 2} more vulnerabilities
                                </p>
                              )}
                            </div>
                          </div>
                        ))}
                      
                      {scanResult.dependencies.every(dep => dep.vulnerabilities.length === 0) && (
                        <div className="rounded-lg border border-[#355952] bg-[#355952]/10 p-4 text-center">
                          <CheckCircle2 className="mx-auto h-8 w-8 text-[#355952]" />
                          <p className="mt-2 text-sm text-[#355952]">No vulnerabilities found</p>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            </TerminalBox>
          </motion.section>
        </div>
      </main>
    </>
  )
}
