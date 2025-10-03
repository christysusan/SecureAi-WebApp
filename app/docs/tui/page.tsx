import Link from "next/link"
import { Header } from "@/components/layout/header"
import { TerminalBox } from "@/components/layout/terminal-box"
import {
  ArrowLeft,
  Terminal,
  Download,
  Settings,
  Keyboard,
  Rocket,
  Shield,
  Wrench,
  Bug
} from "lucide-react"

const requirements = [
  {
    title: "Install dependencies",
    description: "Add the rich terminal libraries required by the TUI interface.",
    command: "pip install textual rich"
  },
  {
    title: "Project requirements",
    description: "Install the full project requirements if you have not already.",
    command: "pip install -r requirements.txt"
  }
]

const launchOptions = [
  {
    label: "CLI command",
    command: "secureai tui",
    note: "Preferred method once the package is installed."
  },
  {
    label: "Demo script",
    command: "python demo_tui.py",
    note: "Run the included showcase script for a guided experience."
  },
  {
    label: "Module execution",
    command: "python -m src.tui",
    note: "Directly execute the TUI module while developing."
  }
]

const shortcuts = [
  { combo: "H", action: "Return to the welcome dashboard" },
  { combo: "S", action: "Jump to Security Scan screen" },
  { combo: "A", action: "Open AI Assessment" },
  { combo: "C", action: "View configuration panel" },
  { combo: "Ctrl+S", action: "Start scan from the Scan screen" },
  { combo: "Ctrl+A", action: "Trigger AI assessment from the AI screen" },
  { combo: "Esc", action: "Go back or dismiss modals" },
  { combo: "Q", action: "Quit the TUI" }
]

const troubleshooting = [
  {
    icon: Wrench,
    title: "Module not found",
    message: "Install the missing libraries with `pip install textual rich`."
  },
  {
    icon: Bug,
    title: "AI assessment fails",
    message: "Verify API keys via the web config page or run `secureai setup`."
  },
  {
    icon: Shield,
    title: "Display issues",
    message: "Use a Unicode-friendly terminal such as Windows Terminal, iTerm2, or Alacritty."
  }
]

export default function TuiDocsPage() {
  return (
    <>
      <Header />
      <main className="min-h-screen bg-background text-foreground">
        <div className="mx-auto max-w-6xl px-4 py-8">
          <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
            <Link
              href="/docs"
              className="inline-flex items-center gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to documentation
            </Link>
            <div className="inline-flex items-center gap-2 rounded border border-brand/30 bg-brand/10 px-3 py-1.5 text-xs font-medium text-brand">
              <Terminal className="h-4 w-4" />
              SecureAI TUI Guide
            </div>
          </div>

          <section className="mb-8">
            <h1 className="mb-3 flex items-center gap-3 text-4xl font-semibold">
              <Terminal className="h-10 w-10 text-brand" />
              Launching the SecureAI TUI
            </h1>
            <p className="max-w-3xl text-lg text-muted-foreground">
              The Text User Interface mirrors the full SecureAI analysis experience inside your terminal. Use it for
              rapid scans, AI-powered assessments, and offline workflows when the web UI is unavailable.
            </p>
          </section>

          <div className="grid gap-6 lg:grid-cols-2">
            <TerminalBox title="Setup Requirements">
              <div className="space-y-4">
                {requirements.map(({ title, description, command }) => (
                  <div key={title} className="rounded-lg border border-border bg-surface p-4">
                    <div className="mb-1 font-semibold text-brand">{title}</div>
                    <p className="mb-2 text-sm text-muted-foreground">{description}</p>
                    <pre className="overflow-x-auto rounded bg-muted/40 p-3 text-xs text-foreground/80">
{command}
                    </pre>
                  </div>
                ))}
              </div>
            </TerminalBox>

            <TerminalBox title="Launch Methods">
              <div className="space-y-4">
                {launchOptions.map(({ label, command, note }) => (
                  <div key={label} className="rounded-lg border border-border bg-surface p-4">
                    <div className="mb-2 flex items-center justify-between">
                      <span className="font-semibold text-brand">{label}</span>
                      <Rocket className="h-4 w-4 text-brand" />
                    </div>
                    <pre className="overflow-x-auto rounded bg-muted/40 p-3 text-xs text-foreground/80">
{command}
                    </pre>
                    <p className="mt-2 text-xs text-muted-foreground/80">{note}</p>
                  </div>
                ))}
              </div>
            </TerminalBox>
          </div>

          <div className="mt-6 grid gap-6 lg:grid-cols-2">
            <TerminalBox title="Essential Shortcuts">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {shortcuts.map(({ combo, action }) => (
                  <div key={combo} className="rounded border border-border bg-surface px-3 py-2">
                    <div className="font-mono text-sm text-brand">{combo}</div>
                    <p className="text-xs text-muted-foreground">{action}</p>
                  </div>
                ))}
              </div>
            </TerminalBox>

            <TerminalBox title="Screen Overview">
              <ul className="space-y-3 text-sm text-muted-foreground">
                <li className="flex items-start gap-2">
                  <Download className="mt-1 h-4 w-4 text-brand" />
                  <span><strong>Welcome:</strong> Quick access cards for scans, AI assessments, configuration, and history.</span>
                </li>
                <li className="flex items-start gap-2">
                  <Shield className="mt-1 h-4 w-4 text-brand" />
                  <span><strong>Security Scan:</strong> Target selection, progress visualisation, and severity breakdown in real time.</span>
                </li>
                <li className="flex items-start gap-2">
                  <Settings className="mt-1 h-4 w-4 text-brand" />
                  <span><strong>AI Assessment:</strong> Generates holistic scores with category insights and remediation tips.</span>
                </li>
                <li className="flex items-start gap-2">
                  <Keyboard className="mt-1 h-4 w-4 text-brand" />
                  <span><strong>Configuration:</strong> Review AI connectivity, key status, and tweak scanning defaults before execution.</span>
                </li>
              </ul>
            </TerminalBox>
          </div>

          <TerminalBox title="Troubleshooting" className="mt-6">
            <div className="grid gap-4 md:grid-cols-3">
              {troubleshooting.map(({ icon: Icon, title, message }) => (
                <div key={title} className="rounded-lg border border-border bg-surface p-4">
                  <Icon className="mb-2 h-5 w-5 text-brand" />
                  <div className="mb-1 font-semibold text-foreground">{title}</div>
                  <p className="text-xs leading-relaxed text-muted-foreground">{message}</p>
                </div>
              ))}
            </div>
          </TerminalBox>

          <div className="mt-10 text-center text-sm text-muted-foreground/80">
            Need a deeper dive? Explore the project README or open an issue for guidance.
          </div>
        </div>
      </main>
    </>
  )
}
