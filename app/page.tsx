"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { Scan, Brain, Terminal, Database, Lock, Newspaper } from "lucide-react";
import { Header } from "@/components/layout/header";
import { TerminalBox } from "@/components/layout/terminal-box";

// Minimal animated background elements
function BackgroundElements() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      <div className="absolute top-20 left-8 w-64 h-64 border border-[#355952]/20 rounded-lg rotate-12 opacity-40" />
      <div className="absolute bottom-32 right-16 w-48 h-48 border border-[#E37769]/20 rounded-lg -rotate-6 opacity-30" />
      <div className="absolute top-1/2 left-1/4 w-2 h-32 bg-gradient-to-b from-[#355952]/20 to-transparent" />
    </div>
  );
}

const technicalFeatures = [
  {
    icon: Scan,
    title: "OneStop-CYworld Basic Scan",
    description: "Upload individual files or entire project folders for comprehensive static analysis across 30+ languages, detecting injection flaws, secrets, crypto issues, and access control vulnerabilities.",
    metrics: "Detectors: SQL/NoSQL/LDAP Injection · XXE · Template Injection · JWT 'none' · File Upload · Mass Assignment"
  },
  {
    icon: Brain,
    title: "AI-Assisted Code Review",
    description: "Send snippets to OpenAI, Anthropic, or Gemini through our encrypted proxy and receive structured CWE-mapped vulnerability reports with remediation steps.",
    metrics: "Providers: OpenAI · Anthropic · Gemini · Configurable confidence"
  },
  {
    icon: Database,
    title: "Dependency Vulnerability Scanner",
    description: "Parse requirements.txt, package.json, go.mod, or pasted manifests and query OSV.dev for CVEs, fixed versions, and prioritised remediation guidance.",
    metrics: "Coverage: OSV API · 50 dependencies per scan · AI remediation playbooks"
  },
  {
    icon: Lock,
    title: "Password Breach Lookup",
    description: "Check password strength with SHA-1 k-anonymity against Have I Been Pwned while keeping full hashes local and visualising the verification flow.",
    metrics: "Features: Local hashing · HIBP range API · Animated verification trail"
  },
  // {
  //   icon: Newspaper,
  //   title: "Security Intelligence Feed",
  //   description: "Track the latest security incidents and research headlines with automatically refreshed summaries and direct source links.",
  //   metrics: "Sources: Cybersecurity news APIs · Hourly refresh · Severity tagging"
  // }
];

export default function HomePage() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => { setMounted(true); }, []);
  if (!mounted) {
    return (
      <>
        <Header />
        <main className="relative mx-auto max-w-7xl px-4 py-8">
          <div className="animate-pulse">
            <div className="mx-auto mb-4 h-8 w-3/4 rounded bg-muted"></div>
            <div className="mx-auto mb-8 h-4 w-1/2 rounded bg-muted"></div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="h-32 rounded bg-muted"></div>
              ))}
            </div>
          </div>
        </main>
      </>
    );
  }
  return (
    <>
      <Header />
      <main className="relative mx-auto max-w-7xl px-4 py-8 text-foreground">
        <BackgroundElements />

        {/* Hero Section */}
        <motion.div 
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="mb-16 text-center"
        >
          <motion.h1 
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2, duration: 0.6 }}
            className="mb-6 text-4xl font-bold text-foreground md:text-6xl lg:text-7xl"
          >
            <span className="text-brand">OneStop</span>-CYworld
          </motion.h1>
          <motion.p 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.6 }}
            className="mx-auto mb-8 max-w-4xl text-xl leading-relaxed text-muted-foreground md:text-2xl"
          >
            Scan your code for security flaws instantly with regex and AI-powered analysis, then stay informed with curated security intelligence updates.
          </motion.p>
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.6, duration: 0.6 }}
            className="flex flex-wrap items-center justify-center gap-4 text-sm text-muted-foreground"
          >
            <span className="rounded-full border border-brand/40 bg-brand/15 px-4 py-2 font-semibold text-brand">
              Research Project v1.1.0
            </span>
            <span className="flex items-center gap-2">
              <Database className="h-4 w-4 text-brand" />
              CVE Database Integration
            </span>
            <span className="flex items-center gap-2">
              <Brain className="h-4 w-4 text-brand" />
              AI-Enhanced Detection
            </span>
          </motion.div>
        </motion.div>

       

        {/* Technical Features */}
        <motion.div 
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.6, duration: 0.8 }}
          className="mb-12"
        >
          <TerminalBox title="Platform Capabilities">
            <div className="grid gap-8 md:grid-cols-2">
              {technicalFeatures.map((feature, index) => {
                const IconComponent = feature.icon;
                return (
                  <motion.div
                    key={feature.title}
                    initial={{ opacity: 0, x: index % 2 === 0 ? -20 : 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 1.8 + index * 0.2, duration: 0.6 }}
                    className="rounded-xl border border-border bg-card p-6 shadow-sm transition-colors hover:border-brand/70"
                  >
                    <div className="mb-4 flex items-start gap-4">
                      <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-lg border border-brand/30 bg-brand/15 text-brand">
                        <IconComponent className="h-6 w-6" />
                      </div>
                      <div>
                        <h3 className="mb-2 font-semibold text-foreground">{feature.title}</h3>
                        <p className="mb-3 text-sm leading-relaxed text-muted-foreground">{feature.description}</p>
                        <p className="font-mono text-xs text-brand">{feature.metrics}</p>
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </TerminalBox>
        </motion.div>

        {/* Research Information */}
        <motion.div 
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 3.0, duration: 0.8 }}
        >
          <TerminalBox title="Academic Research Context">
            <div className="rounded-xl border border-border bg-card p-6 shadow-sm">
              <p className="mb-4 leading-relaxed text-muted-foreground">
                This security analysis platform represents a comprehensive approach to automated vulnerability detection, 
                combining traditional static analysis techniques . The project 
                demonstrates advanced software engineering principles, cybersecurity expertise, and research-driven development.
              </p>
              <div className="grid gap-6 text-sm md:grid-cols-3">
                <div>
                  <h4 className="mb-2 font-semibold text-brand">Research Areas</h4>
                  <ul className="space-y-1 text-muted-foreground">
                    <li>• Static Code Analysis</li>
                    <li>• AI Security</li>
                    <li>• Vulnerability Assessment</li>
                    <li>• Security Intelligence</li>
                  </ul>
                </div>
                <div>
                  <h4 className="mb-2 font-semibold text-brand">Technical Stack</h4>
                  <ul className="space-y-1 text-muted-foreground">
                    <li>• Python AST Parsing</li>
                    <li>• React/Next.js Frontend</li>
                    <li>• SQLite Database</li>
                    {/* TUI Implementation removed */}
                  </ul>
                </div>
                <div>
                  <h4 className="mb-2 font-semibold text-brand">Deliverables</h4>
                  <ul className="space-y-1 text-muted-foreground">
                    <li>• Web Application</li>
                    <li>• Command Line Tool</li>
                    <li>• Security Intelligence Feed</li>
                    <li>• Technical Documentation</li>
                  </ul>
                </div>
              </div>
            </div>
          </TerminalBox>
        </motion.div>
      </main>
    </>
  );
}
