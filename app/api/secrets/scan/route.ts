import { NextResponse } from "next/server"
import { tmpdir } from "os"
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, readdirSync, statSync } from "fs"
import { join, resolve } from "path"
import { spawn } from "child_process"

export const runtime = "nodejs"

type SecretFinding = {
  file: string
  line: number | null
  rule: string
  description: string
  match?: string
  severity?: "critical" | "high" | "medium" | "low"
}

function dirWalk(root: string, out: string[] = []): string[] {
  const entries = readdirSync(root)
  for (const name of entries) {
    const full = join(root, name)
    const st = statSync(full)
    const rel = full
    if (st.isDirectory()) {
      // Skip large and irrelevant directories
      if ([".git", "node_modules", ".next", "dist", "build", "out", "coverage"].includes(name)) continue
      dirWalk(full, out)
    } else {
      out.push(rel)
    }
  }
  return out
}

// Simple regex fallback for common secrets when gitleaks isn't available
const FALLBACK_RULES: Array<{ id: string; re: RegExp; desc: string; severity: SecretFinding["severity"] }> = [
  { id: "aws_access_key", re: /AKIA[0-9A-Z]{16}/g, desc: "AWS Access Key ID pattern detected", severity: "high" },
  { id: "aws_secret_key", re: /aws(.{0,20})?(secret|access)_?(key|token)['"\s:=]+([A-Za-z0-9\/+=]{40})/gi, desc: "AWS Secret Key-like token", severity: "high" },
  { id: "google_api_key", re: /AIza[0-9A-Za-z\-_]{35}/g, desc: "Google API Key pattern", severity: "high" },
  { id: "private_key", re: /-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/g, desc: "Embedded private key", severity: "critical" },
  { id: "generic_token", re: /(api[_-]?key|secret|token|password)\s*[:=]\s*['"][^'"\n]{8,}['"]/gi, desc: "Generic credential assignment", severity: "medium" },
]

async function runCommand(cmd: string, args: string[], cwd?: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolveCmd) => {
    const child = spawn(cmd, args, { cwd, shell: process.platform === "win32" })
    let stdout = ""
    let stderr = ""
    child.stdout.on("data", (d) => (stdout += d.toString()))
    child.stderr.on("data", (d) => (stderr += d.toString()))
    child.on("close", (code) => resolveCmd({ code: code ?? 0, stdout, stderr }))
  })
}

function parseGitleaksJson(jsonStr: string): SecretFinding[] {
  try {
    const data = JSON.parse(jsonStr)
    // gitleaks JSON is usually an array of findings
    if (Array.isArray(data)) {
      return data.map((f: any) => ({
        file: f?.File || f?.file || f?.Location?.File || "",
        line: f?.StartLine || f?.Line || null,
        rule: f?.RuleID || f?.Description || "gitleaks_rule",
        description: f?.Description || f?.RuleID || "Secret detected by gitleaks",
        match: f?.Match || f?.Secret || undefined,
        severity: "high",
      }))
    }
  } catch {}
  return []
}

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({})) as { repoUrl?: string; includeHistory?: boolean }
    const repoUrl = (body.repoUrl || "").trim()
    const includeHistory = Boolean(body.includeHistory)
    if (!repoUrl || !/^https?:\/\/github\.com\//i.test(repoUrl)) {
      return NextResponse.json({ error: "INVALID_INPUT", message: "Provide a valid GitHub repository URL" }, { status: 400 })
    }

    // Prepare temp dir
    const tmp = mkdtempSync(join(tmpdir(), "secureai-secrets-"))
    const repoDir = join(tmp, "repo")

    // Try using git to clone repository
    let cloned = false
    try {
      const cloneRes = await runCommand("git", ["clone", "--depth", includeHistory ? "50" : "1", repoUrl, repoDir])
      if (cloneRes.code === 0) cloned = true
      else {
        return NextResponse.json({ error: "CLONE_FAILED", message: `Failed to clone repository: ${cloneRes.stderr || cloneRes.stdout}` }, { status: 500 })
      }
    } catch (e: any) {
      return NextResponse.json({ error: "GIT_UNAVAILABLE", message: `Git not available: ${e?.message || e}` }, { status: 500 })
    }

    const findings: SecretFinding[] = []
    let usedGitleaks = false

    // Attempt to run gitleaks if present in PATH
    try {
      const reportPath = join(tmp, "gitleaks-report.json")
      const args = [
        "detect",
        "--source", repoDir,
        "--report-format", "json",
        "--report-path", reportPath,
        "--redact",
      ]
      // If only scanning current content, add --no-git
      if (!includeHistory) args.push("--no-git")
      const res = await runCommand("gitleaks", args)
      if (res.code === 0 && existsSync(reportPath)) {
        const json = readFileSync(reportPath, "utf8")
        findings.push(...parseGitleaksJson(json))
        usedGitleaks = true
      }
    } catch {}

    // Fallback: simple regex scan when gitleaks isn't available
    if (!usedGitleaks) {
      const files = dirWalk(repoDir)
      for (const f of files) {
        try {
          const content = readFileSync(f, "utf8")
          for (const rule of FALLBACK_RULES) {
            let m: RegExpExecArray | null
            const re = new RegExp(rule.re.source, rule.re.flags)
            while ((m = re.exec(content)) !== null) {
              // compute line number
              const upto = content.slice(0, m.index)
              const line = upto.split(/\r?\n/).length
              findings.push({
                file: f.replace(repoDir + "\\", "").replace(repoDir + "/", ""),
                line,
                rule: rule.id,
                description: rule.desc,
                match: m[0]?.slice(0, 8) + "…",
                severity: rule.severity,
              })
              if (findings.length > 500) break
            }
            if (findings.length > 500) break
          }
        } catch {}
        if (findings.length > 1000) break
      }
    }

    // Cleanup temp dir (best-effort)
    try { rmSync(tmp, { recursive: true, force: true }) } catch {}

    return NextResponse.json({
      ok: true,
      usedGitleaks,
      findings: findings.slice(0, 1000),
    })
  } catch (e: any) {
    return NextResponse.json({ error: "UNEXPECTED", message: e?.message || String(e) }, { status: 500 })
  }
}
