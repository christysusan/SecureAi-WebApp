"use client"

import { FormEvent, useEffect, useMemo, useState } from "react"
import { motion } from "framer-motion"
import { AlertTriangle, ArrowRight, Eye, EyeOff, Loader2, ShieldCheck } from "lucide-react"

import { BackgroundOrnaments } from "@/components/decor/background-ornaments"
import { Header } from "@/components/layout/header"
import { TerminalBox } from "@/components/layout/terminal-box"
import { cn } from "@/lib/utils"

type CheckState = "idle" | "checking" | "safe" | "pwned" | "error"

interface PwnedResult {
  count: number
  hash: string
  prefix: string
  suffix: string
}

const flowStages = [
  {
    title: "Local hashing",
    description: "Your password never leaves the browser. We create a SHA-1 hash locally.",
  },
  {
    title: "Prefix split",
    description: "Only the first 5 characters of the hash are kept for the lookup.",
  },
  {
    title: "HIBP query",
    description: "We call Have I Been Pwned with the prefix using the k-anonymity range API.",
  },
  {
    title: "Local comparison",
    description: "We compare the returned hash suffixes locally against yours.",
  },
  {
    title: "Exposure result",
    description: "If a match is found, we report how many times the password appeared in breaches.",
  },
]

const bufferToHex = (buffer: ArrayBuffer): string => {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase()
}

const maskHash = (hash: string): string => {
  if (hash.length <= 10) return hash
  return `${hash.slice(0, 6)}••••••${hash.slice(-4)}`
}

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

export default function PassStrengthPage() {
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [state, setState] = useState<CheckState>("idle")
  const [activeStage, setActiveStage] = useState(0)
  const [result, setResult] = useState<PwnedResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!password) {
      setState("idle")
      setActiveStage(0)
      setResult(null)
      setError(null)
    }
  }, [password])

  const passwordScore = useMemo(() => {
    const base = password.length
    const charsetBonus =
      Number(/[A-Z]/.test(password)) +
      Number(/[a-z]/.test(password)) +
      Number(/[0-9]/.test(password)) +
      Number(/[^A-Za-z0-9]/.test(password))
    return Math.min(100, base * 4 + charsetBonus * 5)
  }, [password])

  const handleCheck = async (event: FormEvent) => {
    event.preventDefault()
    setError(null)

    if (!password) {
      setState("error")
      setError("Enter a password to analyze.")
      return
    }

    setState("checking")
    setActiveStage(1)
    setResult(null)

    try {
      await wait(200)

      const data = new TextEncoder().encode(password)
      const hashBuffer = await crypto.subtle.digest("SHA-1", data)
      const hash = bufferToHex(hashBuffer)

      setActiveStage(2)
      await wait(160)

      const prefix = hash.slice(0, 5)
      const suffix = hash.slice(5)

      setActiveStage(3)

      const response = await fetch(`/api/pwned?prefix=${prefix}`)
      if (!response.ok) {
        throw new Error("Unable to reach Have I Been Pwned. Try again later.")
      }

      const payload = (await response.json()) as { matches?: string }
      const lines = payload.matches?.split("\n") ?? []

      setActiveStage(4)
      await wait(120)

      const match = lines
        .map((line) => line.trim().split(":"))
        .find(([hashSuffix]) => hashSuffix?.toUpperCase() === suffix)

      const count = match ? Number.parseInt(match[1] ?? "0", 10) || 0 : 0

      setActiveStage(5)
      await wait(120)

      setResult({ count, hash, prefix, suffix })
      setState(count > 0 ? "pwned" : "safe")
    } catch (err) {
      setState("error")
      setError(err instanceof Error ? err.message : "Unexpected error occurred.")
      setActiveStage(0)
      setResult(null)
    }
  }

  const statusCard = useMemo(() => {
    if (state === "idle") {
      return {
        icon: ShieldCheck,
        tone: "text-foreground/70",
        title: "Ready to check",
        message: "Use the k-anonymity lookup to see if your password surfaced in known breaches.",
      }
    }

    if (state === "checking") {
      return {
        icon: Loader2,
        tone: "text-brand",
        title: "Checking Have I Been Pwned",
        message: "Hashing locally, querying the range API, and comparing results...",
        animate: true,
      }
    }

    if (state === "pwned" && result) {
      return {
        icon: AlertTriangle,
        tone: "text-destructive",
        title: "Password found in breaches",
        message: `This password appeared ${result.count.toLocaleString()} times. Choose a unique, complex password immediately.`,
      }
    }

    if (state === "safe" && result) {
      return {
        icon: ShieldCheck,
        tone: "text-emerald-500",
        title: "No breach matches detected",
        message: "This password was not found in the Have I Been Pwned dataset. Still, avoid reusing passwords across services.",
      }
    }

    return {
      icon: AlertTriangle,
      tone: "text-destructive",
      title: "Unable to check password",
      message: error ?? "We could not complete the lookup. Please retry in a moment.",
    }
  }, [error, result, state])

  const StatusIcon = statusCard.icon

  return (
    <>
      <Header />
      <main className="relative mx-auto max-w-6xl px-4 py-8">
        <BackgroundOrnaments />

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-10 flex flex-col gap-4">
          <div>
            <h1 className="text-4xl font-semibold text-foreground">Pass Strength & Breach Check</h1>
            <p className="mt-3 max-w-2xl text-base text-foreground/80">
              Instantly verify if a password appeared in public breaches using Have I Been Pwned&apos;s privacy-preserving range API.
              We never store or transmit your full password.
            </p>
          </div>
        </motion.div>

        <div className="grid gap-6 lg:grid-cols-[2fr_3fr]">
          <motion.section
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="flex flex-col gap-6"
          >
            <TerminalBox title="Check password" className="overflow-hidden">
              <form onSubmit={handleCheck} className="flex flex-col gap-4">
                <label className="flex flex-col gap-2">
                  <span className="text-sm font-medium text-foreground">Password</span>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      className="w-full rounded-lg border border-border bg-surface px-4 py-3 text-base text-foreground shadow-sm transition focus-visible:border-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
                      placeholder="Enter password to check"
                      autoComplete="off"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((prev) => !prev)}
                      className="absolute inset-y-0 right-3 flex items-center text-foreground/60 transition hover:text-foreground"
                      aria-label={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </label>

                <div>
                  <div className="mb-1 flex items-center justify-between text-xs text-foreground/70">
                    <span>Estimated entropy</span>
                    <span>{passwordScore}%</span>
                  </div>
                  <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                    <motion.div
                      className={cn("h-full", passwordScore > 80 ? "bg-emerald-500" : passwordScore > 50 ? "bg-amber-500" : "bg-destructive")}
                      initial={{ width: 0 }}
                      animate={{ width: `${passwordScore}%` }}
                      transition={{ ease: "easeOut", duration: 0.6 }}
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-brand px-4 py-2 text-sm font-semibold text-white shadow transition hover:bg-brand/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
                  disabled={state === "checking"}
                >
                  {state === "checking" ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Checking...
                    </>
                  ) : (
                    <>
                      Check password
                      <ArrowRight className="h-4 w-4" />
                    </>
                  )}
                </button>

                {state === "error" && error ? (
                  <p className="text-sm text-destructive">{error}</p>
                ) : (
                  <p className="text-xs text-foreground/70">
                    Tip: Use this for spot checks only. For stronger protection, switch to a password manager with breach monitoring.
                  </p>
                )}
              </form>
            </TerminalBox>

            <TerminalBox title="Result" className="space-y-4">
              <div className="flex items-start gap-3">
                <span className={cn("rounded-full bg-muted p-2", statusCard.tone)}>
                  <StatusIcon className={cn("h-5 w-5", statusCard.animate ? "animate-spin" : "")} />
                </span>
                <div>
                  <h3 className="text-base font-semibold text-foreground">{statusCard.title}</h3>
                  <p className="mt-1 text-sm text-foreground/80">{statusCard.message}</p>
                </div>
              </div>

              {result && (
                <div className="grid gap-2 rounded-lg border border-border bg-surface/60 p-4 text-sm text-foreground/80">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-foreground">SHA-1 hash</span>
                    <code className="rounded bg-muted px-2 py-1 text-xs font-mono text-foreground/80">{maskHash(result.hash)}</code>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-foreground">Prefix sent</span>
                    <code className="rounded bg-muted px-2 py-1 text-xs font-mono text-foreground/80">{result.prefix}</code>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-foreground">Local suffix</span>
                    <code className="rounded bg-muted px-2 py-1 text-xs font-mono text-foreground/80">{result.suffix.slice(0, 5)}••••••</code>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-foreground">Breach count</span>
                    <span className={cn("font-semibold", result.count > 0 ? "text-destructive" : "text-emerald-500")}>{result.count.toLocaleString()}</span>
                  </div>
                </div>
              )}
            </TerminalBox>
          </motion.section>

          <motion.section
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="flex flex-col gap-6"
          >
            <TerminalBox title="How the k-anonymity check flows" className="relative overflow-hidden">
              <div className="relative grid gap-4">
                {flowStages.map((stage, index) => {
                  const stageNumber = index + 1
                  const reached = activeStage >= stageNumber || state === "safe" || state === "pwned"
                  return (
                    <motion.div
                      key={stage.title}
                      initial={{ opacity: 0, y: 16 }}
                      animate={{
                        opacity: reached ? 1 : 0.45,
                        y: reached ? 0 : 8,
                        scale: reached ? 1 : 0.98,
                      }}
                      transition={{ delay: index * 0.08 }}
                      className={cn(
                        "relative rounded-xl border border-border bg-surface/70 p-4 backdrop-blur",
                        reached ? "shadow-[0_18px_45px_-20px_rgba(15,23,42,0.45)]" : "",
                      )}
                    >
                      <div className="flex items-start gap-3">
                        <div
                          className={cn(
                            "mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border text-sm font-semibold",
                            reached ? "bg-brand/10 text-brand" : "bg-muted text-foreground/70",
                          )}
                        >
                          {stageNumber}
                        </div>
                        <div>
                          <h4 className="text-sm font-semibold text-foreground">{stage.title}</h4>
                          <p className="mt-1 text-xs leading-relaxed text-foreground/75">{stage.description}</p>
                        </div>
                      </div>
                      {index < flowStages.length - 1 && (
                        <div className="pointer-events-none absolute left-9 top-full z-0 h-6 w-px bg-border" />
                      )}
                    </motion.div>
                  )
                })}
              </div>
            </TerminalBox>

            <TerminalBox title="Why it matters" className="space-y-3 text-sm text-foreground/80">
              <p>
                Have I Been Pwned maintains billions of breached passwords. By checking your password with k-anonymity,
                you learn if attackers have already seen it—without exposing the full password to any service, including us.
              </p>
              <ul className="list-disc space-y-2 pl-5">
                <li>Rotate any password that appears in breaches and avoid reusing it across accounts.</li>
                <li>Prefer passphrases or randomly generated passwords stored in a reputable manager.</li>
                <li>Enable multi-factor authentication to mitigate damage even if a password leaks.</li>
              </ul>
            </TerminalBox>
          </motion.section>
        </div>
      </main>
    </>
  )
}
