'use client'

import Link from "next/link"
import { Code, Shield, FileText, BookOpen, AlertTriangle, Target, ArrowLeft, Terminal } from "lucide-react"

import { Header } from "@/components/layout/header"

const sectionBase = "mb-8 rounded-xl border border-border bg-card p-6 shadow-sm"

export default function DocsPage() {
  return (
    <>
      <Header />
      <main className="min-h-screen bg-background text-foreground">
        <div className="mx-auto max-w-6xl px-4 py-8">
          <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
            <Link
              href="/"
              className="inline-flex items-center gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to dashboard
            </Link>
            <Link
              href="/docs/tui"
              className="inline-flex items-center gap-2 rounded border border-brand/30 bg-brand/10 px-3 py-1.5 text-xs font-medium text-brand transition-colors hover:bg-brand/15"
            >
              <Terminal className="h-4 w-4" />
              TUI Quickstart Guide
            </Link>
          </div>
        {/* Header */}
        <div className="mb-8">
          <h1 className="mb-4 flex items-center gap-3 text-4xl font-semibold">
            <BookOpen className="h-10 w-10 text-brand" />
            Documentation
          </h1>
          <p className="text-xl text-muted-foreground">
            Comprehensive guide to university-level security analysis platform
          </p>
        </div>

        {/* Overview */}
        <section className={sectionBase}>
          <div className="mb-4 flex items-center gap-2 text-2xl font-semibold text-brand">
            <Shield className="h-6 w-6" />
            <span>Platform Overview</span>
          </div>
          <div className="space-y-4 text-muted-foreground">
            <p>
              This platform represents a university-level security analysis solution that combines 
              advanced static code analysis with AI-enhanced vulnerability detection. It bridges 
              the gap between academic research and practical security implementation.
            </p>
            <div className="grid md:grid-cols-3 gap-4 mt-6">
              <div className="rounded-lg border border-border bg-surface p-4">
                <h3 className="mb-2 font-semibold text-brand">Academic Excellence</h3>
                <p className="text-sm text-muted-foreground/80">Research-grade methodologies with peer-reviewed detection algorithms</p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-4">
                <h3 className="mb-2 font-semibold text-brand">Industry Standards</h3>
                <p className="text-sm text-muted-foreground/80">Enterprise-level security scanning with professional reporting</p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-4">
                <h3 className="mb-2 font-semibold text-brand">AI Integration</h3>
                <p className="text-sm text-muted-foreground/80">Machine learning enhanced analysis with contextual understanding</p>
              </div>
            </div>
          </div>
        </section>

        {/* Research Methodology */}
        <section className={sectionBase}>
          <div className="mb-4 flex items-center gap-2 text-2xl font-semibold text-brand">
            <Target className="h-6 w-6" />
            <span>Research Methodology</span>
          </div>
          <div className="space-y-4 text-muted-foreground">
            <h3 className="text-lg font-semibold text-foreground">Vulnerability Detection Approach</h3>
            <ul className="space-y-2 pl-4">
              <li className="flex items-start gap-2">
                <span className="mt-1 inline-block rounded border border-brand px-2 py-1 text-xs text-brand">AST</span>
                <span>Abstract Syntax Tree analysis for deep code understanding</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-1 inline-block rounded border border-brand px-2 py-1 text-xs text-brand">ML</span>
                <span>Machine learning pattern recognition for emerging threats</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-1 inline-block rounded border border-brand px-2 py-1 text-xs text-brand">CVE</span>
                <span>Real-time CVE database integration and correlation</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-1 inline-block rounded border border-brand px-2 py-1 text-xs text-brand">SARIF</span>
                <span>Standards-compliant reporting with SARIF format support</span>
              </li>
            </ul>
          </div>
        </section>

        {/* TUI Tool Integration */}
        <section className={sectionBase}>
          <div className="mb-4 flex items-center gap-2 text-2xl font-semibold text-brand">
            <Code className="h-6 w-6" />
            <span>TUI Tool Integration</span>
          </div>
          <div className="space-y-4 text-muted-foreground">
            <p>
              Our Text User Interface (TUI) tool represents the core command-line implementation 
              of the security analysis engine. This web interface provides configuration and 
              monitoring capabilities for the underlying TUI system.
            </p>
            <div className="rounded-lg border border-border bg-surface p-4">
              <h4 className="mb-2 font-semibold text-brand">Key Features</h4>
              <ul className="space-y-1 text-sm text-muted-foreground/90">
                <li>• Interactive vulnerability scanning with real-time feedback</li>
                <li>• Multiple output formats (JSON, SARIF, HTML, Console)</li>
                <li>• Configurable detection rules and severity thresholds</li>
                <li>• AI-enhanced analysis with provider flexibility</li>
                <li>• Performance profiling and trend analysis</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Configuration Guide */}
        <section className={sectionBase}>
          <div className="mb-4 flex items-center gap-2 text-2xl font-semibold text-brand">
            <FileText className="h-6 w-6" />
            <span>Configuration Guide</span>
          </div>
          <div className="space-y-4 text-muted-foreground">
            <p>
              The configuration page allows you to set up AI providers for enhanced analysis 
              capabilities. This integration enables context-aware vulnerability assessment 
              beyond traditional pattern matching.
            </p>
            <div className="space-y-3">
              <div className="rounded-lg border border-border bg-surface p-3">
                <h4 className="font-semibold text-brand">API Configuration</h4>
                <p className="mt-1 text-sm text-muted-foreground/80">Secure session-based storage of API credentials</p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-3">
                <h4 className="font-semibold text-brand">Session Encryption</h4>
                <p className="mt-1 text-sm text-muted-foreground/80">User-defined passphrase encrypts keys before they’re stored in the browser</p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-3">
                <h4 className="font-semibold text-brand">Provider Selection</h4>
                <p className="mt-1 text-sm text-muted-foreground/80">Support for OpenAI, Anthropic, and other AI providers</p>
              </div>
              <div className="rounded-lg border border-border bg-surface p-3">
                <h4 className="font-semibold text-brand">Analysis Parameters</h4>
                <p className="mt-1 text-sm text-muted-foreground/80">Configurable confidence thresholds and analysis depth</p>
              </div>
            </div>
          </div>
        </section>

        {/* Technical Specifications */}
        <section className={sectionBase}>
          <div className="mb-4 flex items-center gap-2 text-2xl font-semibold text-brand">
            <AlertTriangle className="h-6 w-6" />
            <span>Technical Specifications</span>
          </div>
          <div className="space-y-4 text-muted-foreground">
            <div className="grid gap-6 md:grid-cols-2">
              <div>
                <h4 className="mb-3 font-semibold text-foreground">Supported Languages</h4>
                <div className="space-y-2">
                  <span className="mr-2 inline-block rounded border border-brand px-2 py-1 text-xs text-brand">Python</span>
                  <span className="mr-2 inline-block rounded border border-brand px-2 py-1 text-xs text-brand">JavaScript</span>
                  <span className="mr-2 inline-block rounded border border-brand px-2 py-1 text-xs text-brand">TypeScript</span>
                  <span className="inline-block rounded border border-brand px-2 py-1 text-xs text-brand">Java</span>
                </div>
              </div>
              <div>
                <h4 className="mb-3 font-semibold text-foreground">Detection Categories</h4>
                <div className="space-y-1 text-sm text-muted-foreground/90">
                  <div> SQL Injection & XSS Detection</div>
                  <div> Authentication & Authorization Flaws</div>
                  <div> Cryptographic Vulnerabilities</div>
                  <div> Command Injection & SSRF</div>
                  <div> Dependency Security Analysis</div>
                </div>
              </div>
            </div>
          </div>
        </section>
        </div>
      </main>
    </>
  )
}
