"use client"

import { useMemo, useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import {
  Activity,
  AlertTriangle,
  ShieldCheck,
  ClipboardList,
  RotateCcw
} from "lucide-react"

interface LogEntry {
  id: number
  timestamp: string
  source: string
  message: string
  severity: "INFO" | "WARN" | "ERROR"
  suspicious: boolean
  indicator: string
  insight: string
}

interface HistoryEntry extends LogEntry {
  userChoice: "suspicious" | "benign"
  correct: boolean
}

const LOG_LIBRARY: LogEntry[] = [
  {
    id: 1,
    timestamp: "2025-10-03T10:12:41Z",
    source: "auth-service",
    message: "Failed login for admin from 45.123.22.5",
    severity: "WARN",
    suspicious: true,
    indicator: "Repeated admin login failures",
    insight: "Multiple failed admin logins from an unfamiliar ASN indicates a brute-force attempt."
  },
  {
    id: 2,
    timestamp: "2025-10-03T10:15:02Z",
    source: "web-api",
    message: "GET /v1/users?page=1",
    severity: "INFO",
    suspicious: false,
    indicator: "Typical pagination request",
    insight: "Legitimate paginated request with no unusual parameters."
  },
  {
    id: 3,
    timestamp: "2025-10-03T10:20:18Z",
    source: "db-audit",
    message: "SELECT * FROM credit_cards WHERE id='1' OR '1'='1'",
    severity: "ERROR",
    suspicious: true,
    indicator: "Classic tautology injection",
    insight: "Query contains tautology condition and targets a sensitive table, signalling SQL injection."
  },
  {
    id: 4,
    timestamp: "2025-10-03T10:25:07Z",
    source: "network-gateway",
    message: "Outbound connection to 198.51.100.22:4444",
    severity: "WARN",
    suspicious: true,
    indicator: "Unapproved command-and-control port",
    insight: "Port 4444 is commonly used by reverse shells and the destination is outside the allow-list."
  },
  {
    id: 5,
    timestamp: "2025-10-03T10:26:53Z",
    source: "file-monitor",
    message: "Checksum verified for /usr/local/bin/secureai",
    severity: "INFO",
    suspicious: false,
    indicator: "Integrity check passed",
    insight: "File integrity monitoring confirms no tampering for the SecureAI binary."
  },
  {
    id: 6,
    timestamp: "2025-10-03T10:28:10Z",
    source: "proxy",
    message: "POST /login payload length=1024 user-agent=sqlmap",
    severity: "WARN",
    suspicious: true,
    indicator: "Automated attack tooling detected",
    insight: "User agent advertises sqlmap with unusually large payload typical of injection fuzzing."
  },
  {
    id: 7,
    timestamp: "2025-10-03T10:30:44Z",
    source: "vpn",
    message: "User chris disconnected - session timeout",
    severity: "INFO",
    suspicious: false,
    indicator: "Standard timeout",
    insight: "VPN session ended due to inactivity, matching policy expectations."
  },
  {
    id: 8,
    timestamp: "2025-10-03T10:34:11Z",
    source: "kubernetes",
    message: "Container finance-api restarted 5 times in 2m",
    severity: "ERROR",
    suspicious: true,
    indicator: "Crash loop",
    insight: "High restart count may indicate exploitation attempts or poisoned runtime images."
  },
  {
    id: 9,
    timestamp: "2025-10-03T10:36:59Z",
    source: "email-gateway",
    message: "Outbound email to ceo@company.com subject 'Invoice Q4'",
    severity: "INFO",
    suspicious: false,
    indicator: "Standard outbound mail",
    insight: "Matches legitimate billing workflow, no IOC detected."
  },
  {
    id: 10,
    timestamp: "2025-10-03T10:38:27Z",
    source: "edr",
    message: "Powershell spawned with -EncodedCommand",
    severity: "ERROR",
    suspicious: true,
    indicator: "Obfuscated PowerShell",
    insight: "Encoded PowerShell commands are a strong indicator of post-exploitation activity."
  },
  {
    id: 11,
    timestamp: "2025-10-03T10:41:52Z",
    source: "dns",
    message: "Query for s3-us-west-2.amazonaws.com",
    severity: "INFO",
    suspicious: false,
    indicator: "Common cloud hostname",
    insight: "Frequent legitimate DNS lookup for S3 buckets."
  },
  {
    id: 12,
    timestamp: "2025-10-03T10:43:05Z",
    source: "backup-node",
    message: "Backup job failed: destination share unreachable",
    severity: "WARN",
    suspicious: true,
    indicator: "Critical backups disrupted",
    insight: "Backups failing unexpectedly can indicate ransomware staging or network tampering."
  }
]

const sampleLogs = () => {
  const randomized = [...LOG_LIBRARY].sort(() => Math.random() - 0.5)
  return randomized.slice(0, 7)
}

export default function LogAnalysisGame() {
  const [logQueue, setLogQueue] = useState<LogEntry[]>(() => sampleLogs())
  const [currentIndex, setCurrentIndex] = useState(0)
  const [decision, setDecision] = useState<"suspicious" | "benign" | null>(null)
  const [history, setHistory] = useState<HistoryEntry[]>([])
  const [score, setScore] = useState(0)
  const [correctCount, setCorrectCount] = useState(0)
  const [totalDecisions, setTotalDecisions] = useState(0)

  const currentLog = logQueue[currentIndex]
  const accuracy = totalDecisions > 0 ? Math.round((correctCount / totalDecisions) * 100) : 0

  const feedback = useMemo(() => {
    if (!decision || !currentLog) return null
    const isSuspicious = currentLog.suspicious
    const correctDecision = (decision === "suspicious" && isSuspicious) || (decision === "benign" && !isSuspicious)

    return {
      correctDecision,
      header: correctDecision ? "Great catch!" : "Re-evaluate this log",
      toneClass: correctDecision ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-300" : "border-red-500/40 bg-red-500/10 text-red-200",
      body: currentLog.insight
    }
  }, [decision, currentLog])

  const handleDecision = (choice: "suspicious" | "benign") => {
    if (!currentLog || decision) return

    const isSuspicious = currentLog.suspicious
    const correctDecision = (choice === "suspicious" && isSuspicious) || (choice === "benign" && !isSuspicious)
    setDecision(choice)
    setTotalDecisions((prev) => prev + 1)
    if (correctDecision) {
      setCorrectCount((prev) => prev + 1)
      setScore((prev) => prev + (isSuspicious ? 25 : 15))
    } else {
      setScore((prev) => Math.max(0, prev - 10))
    }

    setHistory((prev) => [
      {
        ...currentLog,
        userChoice: choice,
        correct: correctDecision
      },
      ...prev.slice(0, 7)
    ])
  }

  const nextLog = () => {
    if (currentIndex === logQueue.length - 1) {
      setLogQueue(sampleLogs())
      setCurrentIndex(0)
    } else {
      setCurrentIndex((idx) => idx + 1)
    }
    setDecision(null)
  }

  const resetGame = () => {
    setLogQueue(sampleLogs())
    setCurrentIndex(0)
    setDecision(null)
    setHistory([])
    setScore(0)
    setCorrectCount(0)
    setTotalDecisions(0)
  }

  if (!currentLog) {
    return null
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center mb-6"
      >
        <h1 className="text-3xl font-bold text-[#ff8c00] mb-2 flex items-center justify-center gap-3">
          <Activity className="w-8 h-8" />
          🕵️ Threat Hunter Log Lab
          <ShieldCheck className="w-8 h-8" />
        </h1>
        <p className="text-gray-600 max-w-2xl mx-auto">
          Review inbound security telemetry, flag malicious events, and defend the SOC dashboard in real time.
        </p>
      </motion.div>

      <div className="grid lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="lg:col-span-2 bg-gradient-to-br from-gray-900 to-gray-800 rounded-lg border-2 border-[#ff8c00] p-6 shadow-lg"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="font-mono text-xs text-gray-400">{currentLog.timestamp}</div>
              <div className="text-lg font-semibold text-white">{currentLog.source}</div>
            </div>
            <span
              className={`px-3 py-1 text-xs font-semibold rounded-full ${
                currentLog.severity === "ERROR"
                  ? "bg-red-500/20 text-red-300 border border-red-500/40"
                  : currentLog.severity === "WARN"
                  ? "bg-yellow-500/20 text-yellow-200 border border-yellow-500/40"
                  : "bg-emerald-500/20 text-emerald-200 border border-emerald-500/40"
              }`}
            >
              {currentLog.severity}
            </span>
          </div>

          <div className="rounded-lg border border-gray-700 bg-black/40 p-4 mb-6">
            <p className="font-mono text-sm text-gray-100">{currentLog.message}</p>
          </div>

          <div className="grid sm:grid-cols-2 gap-4 mb-6">
            <motion.button
              whileHover={{ scale: decision ? 1 : 1.03 }}
              whileTap={{ scale: decision ? 1 : 0.97 }}
              onClick={() => handleDecision("suspicious")}
              disabled={!!decision}
              className={`flex items-center justify-center gap-2 rounded-lg border-2 px-4 py-3 font-semibold transition-colors ${
                decision === "suspicious"
                  ? currentLog.suspicious
                    ? "border-emerald-500 bg-emerald-500/20 text-emerald-100"
                    : "border-red-500 bg-red-500/20 text-red-200"
                  : "border-gray-700 bg-gray-900 text-gray-200 hover:border-emerald-500/80 hover:bg-emerald-500/10"
              }`}
            >
              <AlertTriangle className="w-5 h-5" />
              Flag as malicious
            </motion.button>

            <motion.button
              whileHover={{ scale: decision ? 1 : 1.03 }}
              whileTap={{ scale: decision ? 1 : 0.97 }}
              onClick={() => handleDecision("benign")}
              disabled={!!decision}
              className={`flex items-center justify-center gap-2 rounded-lg border-2 px-4 py-3 font-semibold transition-colors ${
                decision === "benign"
                  ? !currentLog.suspicious
                    ? "border-emerald-500 bg-emerald-500/20 text-emerald-100"
                    : "border-red-500 bg-red-500/20 text-red-200"
                  : "border-gray-700 bg-gray-900 text-gray-200 hover:border-blue-500/70 hover:bg-blue-500/10"
              }`}
            >
              <ShieldCheck className="w-5 h-5" />
              Mark as safe
            </motion.button>
          </div>

          <AnimatePresence>
            {feedback && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                className={`rounded-lg border px-4 py-3 mb-6 text-sm ${feedback.toneClass}`}
              >
                <div className="font-semibold mb-1">{feedback.header}</div>
                <div>{feedback.body}</div>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="flex items-center justify-between">
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={resetGame}
              className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:border-[#ff8c00] hover:text-white"
            >
              <RotateCcw className="w-4 h-4" />
              Reset scenario
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={nextLog}
              className="inline-flex items-center gap-2 rounded-lg bg-[#ff8c00] px-4 py-2 text-sm font-semibold text-black hover:bg-[#ff6b35]"
            >
              Review next log
            </motion.button>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg border-2 border-[#ff8c00] p-6"
        >
          <h2 className="text-lg font-semibold text-[#ff8c00] mb-4 flex items-center gap-2">
            <ClipboardList className="w-5 h-5" />
            Analyst Dashboard
          </h2>

          <div className="grid grid-cols-2 gap-3 mb-6">
            <div className="rounded-lg border border-gray-200 bg-white/80 p-3 text-center">
              <div className="text-xl font-bold text-[#ff8c00]">{score}</div>
              <div className="text-xs text-gray-600">Score</div>
            </div>
            <div className="rounded-lg border border-gray-200 bg-white/80 p-3 text-center">
              <div className="text-xl font-bold text-[#ff8c00]">{currentIndex + 1}/{logQueue.length}</div>
              <div className="text-xs text-gray-600">Logs Reviewed</div>
            </div>
            <div className="rounded-lg border border-gray-200 bg-white/80 p-3 text-center">
              <div className="text-xl font-bold text-[#ff8c00]">{correctCount}</div>
              <div className="text-xs text-gray-600">Correct Calls</div>
            </div>
            <div className="rounded-lg border border-gray-200 bg-white/80 p-3 text-center">
              <div className="text-xl font-bold text-[#ff8c00]">{accuracy}%</div>
              <div className="text-xs text-gray-600">Accuracy</div>
            </div>
          </div>

          <div className="border-t border-gray-200 pt-4">
            <h3 className="text-sm font-semibold text-gray-700 mb-3">Last decisions</h3>
            <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
              {history.length === 0 && (
                <p className="text-xs text-gray-500">Make your first decision to build the analyst trail.</p>
              )}
              {history.map((entry) => (
                <div
                  key={entry.id + entry.timestamp + entry.userChoice}
                  className={`rounded border px-3 py-2 text-xs ${
                    entry.correct ? "border-emerald-400/60 bg-emerald-50" : "border-red-400/60 bg-red-50"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-gray-700">{entry.source}</span>
                    <span className="font-mono text-gray-500">{entry.timestamp.split("T")[1]?.replace("Z", "")}</span>
                  </div>
                  <p className="text-gray-600 mb-1">{entry.message}</p>
                  <p className="text-gray-500">
                    You marked <strong>{entry.userChoice}</strong> – {entry.correct ? "correct" : "incorrect"}. Indicator: {entry.indicator}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
