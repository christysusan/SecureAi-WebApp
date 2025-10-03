"use client"

import { useMemo, useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import {
  ShieldAlert,
  CheckCircle2,
  ClipboardCheck,
  RotateCcw,
  Target,
  Lightbulb,
  ChevronRight
} from "lucide-react"

interface ResponseOption {
  label: string
  impact: "ideal" | "acceptable" | "risky"
  explanation: string
  points: number
}

interface ScenarioStep {
  id: string
  prompt: string
  hint: string
  options: ResponseOption[]
}

interface Scenario {
  id: string
  title: string
  description: string
  severity: "High" | "Critical" | "Medium"
  narrative: string
  steps: ScenarioStep[]
  successMessage: string
}

interface TimelineEntry {
  stepId: string
  option: ResponseOption
  stepPrompt: string
}

const SCENARIOS: Scenario[] = [
  {
    id: "ransomware",
    title: "Ransomware Detected on Finance Server",
    severity: "Critical",
    description: "A finance file server begins encrypting files and the SOC receives a ransom note.",
    narrative: "Work through containment, communication, and recovery while preserving evidence.",
    successMessage: "Excellent containment and recovery plan. Stakeholders are informed and data is restored without paying the ransom.",
    steps: [
      {
        id: "containment",
        prompt: "First response: the server is actively encrypting shared drives.",
        hint: "Containment and evidence preservation come first.",
        options: [
          {
            label: "Disconnect the server from the network and capture forensic snapshot",
            impact: "ideal",
            explanation: "Stops lateral movement while preserving volatile evidence for later investigation.",
            points: 30
          },
          {
            label: "Restore last night's backup immediately",
            impact: "acceptable",
            explanation: "Backups are helpful but without containment the ransomware may reinfect during restore.",
            points: 15
          },
          {
            label: "Pay the ransom to regain access quickly",
            impact: "risky",
            explanation: "Paying ransom incentivises attackers and does not guarantee decryption keys.",
            points: -20
          }
        ]
      },
      {
        id: "communication",
        prompt: "Leadership asks for the next update and user guidance.",
        hint: "Clarity and coordination reduce impact.",
        options: [
          {
            label: "Prepare executive briefing and notify legal & PR teams",
            impact: "ideal",
            explanation: "Stakeholders stay aligned and communications are coordinated with regulatory obligations.",
            points: 25
          },
          {
            label: "Silence communication to avoid panic",
            impact: "risky",
            explanation: "Keeping teams uninformed delays remediation and may break disclosure obligations.",
            points: -15
          },
          {
            label: "Message users to power off their machines and await instructions",
            impact: "acceptable",
            explanation: "User awareness reduces spread but leadership still requires broader coordination.",
            points: 15
          }
        ]
      },
      {
        id: "recovery",
        prompt: "After containment, you plan recovery actions.",
        hint: "Validate systems before returning to production.",
        options: [
          {
            label: "Rebuild from clean images and restore validated backups",
            impact: "ideal",
            explanation: "Ensures systems return hardened with clean baselines and verifies data integrity.",
            points: 30
          },
          {
            label: "Re-enable server once encryption stops",
            impact: "risky",
            explanation: "Resuming operations without verifying integrity risks immediate re-encryption.",
            points: -15
          },
          {
            label: "Keep server offline and perform tabletop review only",
            impact: "acceptable",
            explanation: "Lessons learned matter, but operations must resume with validated, clean systems.",
            points: 10
          }
        ]
      }
    ]
  },
  {
    id: "phishing",
    title: "Executive Spear-Phishing Campaign",
    severity: "High",
    description: "Multiple executives report suspicious invoice emails after one user clicked a link.",
    narrative: "Hunt for compromised credentials while strengthening awareness and defenses.",
    successMessage: "Phishing campaign contained, credentials rotated, and awareness campaign launched within 24 hours.",
    steps: [
      {
        id: "scoping",
        prompt: "Initial action when the phishing email is reported.",
        hint: "Quick scoping narrows exposure.",
        options: [
          {
            label: "Collect email headers and block sending domain at the gateway",
            impact: "ideal",
            explanation: "Stops additional delivery and provides indicators for threat hunting.",
            points: 25
          },
          {
            label: "Delete the email from the reporter's inbox only",
            impact: "risky",
            explanation: "Other recipients remain exposed and campaign indicators are lost.",
            points: -10
          },
          {
            label: "Forward the email to everyone warning them",
            impact: "acceptable",
            explanation: "Awareness helps but risks users interacting with malicious content.",
            points: 5
          }
        ]
      },
      {
        id: "credential",
        prompt: "Determine if credentials were compromised after a link was clicked.",
        hint: "Monitoring and forced resets reduce attacker dwell time.",
        options: [
          {
            label: "Force password resets and review authentication logs for anomalies",
            impact: "ideal",
            explanation: "Immediate credential rotation plus log review removes attacker access and surfaces suspicious sessions.",
            points: 30
          },
          {
            label: "Wait to see if unusual access occurs",
            impact: "risky",
            explanation: "Delaying action gives attackers the window to weaponise stolen credentials.",
            points: -15
          },
          {
            label: "Disable MFA temporarily to avoid lockouts",
            impact: "risky",
            explanation: "Weakens defenses during an active campaign and should be avoided.",
            points: -20
          }
        ]
      },
      {
        id: "education",
        prompt: "Post-incident improvements",
        hint: "Reinforce detection and human sensors.",
        options: [
          {
            label: "Launch targeted awareness training with simulated phishing",
            impact: "ideal",
            explanation: "Keeps employees vigilant and improves detection rates of future campaigns.",
            points: 20
          },
          {
            label: "Rely solely on email security gateway",
            impact: "risky",
            explanation: "Technology controls help but phishing is best defeated with layered defenses including people.",
            points: -10
          },
          {
            label: "Add indicators to the SIEM and monitor",
            impact: "acceptable",
            explanation: "Improves detection, though without training the campaign could recur.",
            points: 10
          }
        ]
      }
    ]
  },
  {
    id: "cloud-misconfig",
    title: "Public S3 Bucket Exposing Customer Data",
    severity: "High",
    description: "Security scan reveals a cloud storage bucket with world-readable backups.",
    narrative: "Triage exposure, revoke access, and implement preventative guardrails.",
    successMessage: "Bucket access locked down, exposure assessed, and preventative controls deployed across the fleet.",
    steps: [
      {
        id: "lockdown",
        prompt: "Immediate reaction to the discovery.",
        hint: "Stop the data exposure first.",
        options: [
          {
            label: "Remove public ACLs and block public access policies",
            impact: "ideal",
            explanation: "Instantly revokes anonymous access and brings bucket back under policy control.",
            points: 25
          },
          {
            label: "Rename the bucket to something obscure",
            impact: "risky",
            explanation: "Security through obscurity does not prevent ongoing public access.",
            points: -15
          },
          {
            label: "Copy objects to a new bucket and delete the old one",
            impact: "acceptable",
            explanation: "Helps but may break application dependencies and loses forensic trail.",
            points: 10
          }
        ]
      },
      {
        id: "assessment",
        prompt: "Evaluate what data may have leaked.",
        hint: "Logs and versioning reveal exposure window.",
        options: [
          {
            label: "Review access logs and enable object-level logging for future visibility",
            impact: "ideal",
            explanation: "Determines if data was exfiltrated and strengthens monitoring going forward.",
            points: 25
          },
          {
            label: "Assume no one accessed it because it's hard to find",
            impact: "risky",
            explanation: "Cloud search engines catalogue public buckets quickly; assume compromise until proven otherwise.",
            points: -15
          },
          {
            label: "Notify customers immediately without investigation",
            impact: "acceptable",
            explanation: "Transparency matters but without details communications may be inaccurate.",
            points: 10
          }
        ]
      },
      {
        id: "prevention",
        prompt: "Prevent recurrence across environments.",
        hint: "Enforce guardrails and continuous auditing.",
        options: [
          {
            label: "Deploy infrastructure policy to block public buckets and add automated compliance checks",
            impact: "ideal",
            explanation: "Prevents future misconfigurations and provides continuous detection of drift.",
            points: 30
          },
          {
            label: "Send email reminding engineers to double-check permissions",
            impact: "acceptable",
            explanation: "Awareness helps but without automated guardrails mistakes will recur.",
            points: 10
          },
          {
            label: "Disable all S3 buckets until further notice",
            impact: "risky",
            explanation: "Disrupts business operations unnecessarily and does not address root cause sustainably.",
            points: -20
          }
        ]
      }
    ]
  }
]

export default function IncidentResponseSimulator() {
  const [scenarioIndex, setScenarioIndex] = useState(0)
  const [stepIndex, setStepIndex] = useState(0)
  const [timeline, setTimeline] = useState<TimelineEntry[]>([])
  const [score, setScore] = useState(0)
  const [completed, setCompleted] = useState(false)

  const scenario = SCENARIOS[scenarioIndex]
  const currentStep = scenario.steps[stepIndex]

  const maxScore = useMemo(() => scenario.steps.reduce((total, step) => {
    const best = Math.max(...step.options.map((option) => option.points))
    return total + best
  }, 0), [scenario])

  const progress = Math.round((((completed ? scenario.steps.length : stepIndex) / scenario.steps.length)) * 100)

  const handleOptionSelect = (option: ResponseOption) => {
    setTimeline((prev) => [
      ...prev,
      {
        stepId: currentStep.id,
        option,
        stepPrompt: currentStep.prompt
      }
    ])
    setScore((prev) => Math.max(0, prev + option.points))

    if (stepIndex === scenario.steps.length - 1) {
      setCompleted(true)
    } else {
      setStepIndex((idx) => idx + 1)
    }
  }

  const resetScenario = (newIndex?: number) => {
    if (typeof newIndex === "number") {
      setScenarioIndex(newIndex)
    }
    setStepIndex(0)
    setTimeline([])
    setScore(0)
    setCompleted(false)
  }

  const performanceLevel = useMemo(() => {
    const ratio = maxScore === 0 ? 0 : score / maxScore
    if (ratio >= 0.8) return { label: "Excellent", tone: "text-emerald-400", description: "Incident handled with best practices." }
    if (ratio >= 0.6) return { label: "Strong", tone: "text-blue-300", description: "Good response. Review areas for optimisation." }
    if (ratio >= 0.4) return { label: "Developing", tone: "text-yellow-300", description: "Core actions present but improvements needed." }
    return { label: "Needs Attention", tone: "text-red-300", description: "Revisit fundamentals to strengthen response." }
  }, [score, maxScore])

  return (
    <div className="max-w-6xl mx-auto p-6">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between mb-6"
      >
        <div>
          <h1 className="text-3xl font-bold text-[#ff8c00] mb-1 flex items-center gap-3">
            <ShieldAlert className="w-8 h-8" />
            🎯 Incident Response Simulator
          </h1>
          <p className="text-gray-500 max-w-2xl">
            Make real-time decisions through university-grade cybersecurity incidents. Aim for ideal responses, document your playbook, and learn from each step.
          </p>
        </div>
        <div className="flex gap-3">
          {SCENARIOS.map((item, idx) => (
            <button
              key={item.id}
              onClick={() => resetScenario(idx)}
              className={`rounded-lg border px-3 py-2 text-sm transition-colors ${
                scenarioIndex === idx ? "border-[#ff8c00] text-[#ff8c00] bg-[#ff8c00]/10" : "border-gray-700 text-gray-400 hover:border-[#ff8c00]/50 hover:text-white"
              }`}
            >
              {item.title.split(" ")[0]}
            </button>
          ))}
        </div>
      </motion.div>

      <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="rounded-lg border-2 border-[#ff8c00] bg-gradient-to-br from-gray-900 to-gray-800 p-6 shadow"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="flex items-center gap-2 text-sm text-gray-400 mb-1">
                <Target className="w-4 h-4" />
                {scenario.severity} Severity
              </div>
              <h2 className="text-xl font-semibold text-white">{scenario.title}</h2>
            </div>
            <div className="text-right">
              <div className="text-sm text-gray-400">Progress</div>
              <div className="font-mono text-lg text-[#ff8c00]">{progress}%</div>
            </div>
          </div>
          <p className="text-sm text-gray-300 mb-6">{scenario.description}</p>

          {!completed && (
            <motion.div
              key={currentStep.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-lg border border-gray-700 bg-black/40 p-5"
            >
              <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-[#ff8c00] mb-2">
                <ClipboardCheck className="w-4 h-4" />
                Decision Stage
              </div>
              <h3 className="text-lg font-semibold text-white mb-3">{currentStep.prompt}</h3>
              <p className="text-xs text-gray-400 mb-4">Hint: {currentStep.hint}</p>

              <div className="space-y-3">
                {currentStep.options.map((option) => (
                  <motion.button
                    key={option.label}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => handleOptionSelect(option)}
                    className="w-full text-left rounded-lg border border-gray-700 bg-gray-900/70 px-4 py-3 transition-colors hover:border-[#ff8c00]/70"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-semibold text-gray-100">{option.label}</span>
                      <ChevronRight className="w-4 h-4 text-[#ff8c00]" />
                    </div>
                    <p className="text-xs text-gray-400">{option.explanation}</p>
                  </motion.button>
                ))}
              </div>
            </motion.div>
          )}

          <AnimatePresence>
            {completed && (
              <motion.div
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 30 }}
                className="mt-4 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-5"
              >
                <div className="flex items-center gap-3 mb-2 text-emerald-300">
                  <CheckCircle2 className="w-5 h-5" />
                  Scenario complete
                </div>
                <p className="text-sm text-gray-100 mb-3">{scenario.successMessage}</p>
                <div className="text-xs text-gray-300">Performance: <span className="font-semibold">{performanceLevel.label}</span> — {performanceLevel.description}</div>
                <button
                  onClick={() => resetScenario()}
                  className="mt-4 inline-flex items-center gap-2 rounded border border-gray-700 px-3 py-2 text-xs text-gray-200 hover:border-[#ff8c00] hover:text-white"
                >
                  <RotateCcw className="w-4 h-4" />
                  Replay scenario
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="rounded-lg border-2 border-[#ff8c00] bg-gradient-to-br from-blue-50 to-indigo-50 p-6"
        >
          <h3 className="text-lg font-semibold text-[#ff8c00] mb-4 flex items-center gap-2">
            <Lightbulb className="w-5 h-5" />
            Response Journal
          </h3>

          <div className="grid grid-cols-2 gap-3 mb-5">
            <div className="rounded-lg border border-white/60 bg-white/80 p-3 text-center">
              <div className="text-xl font-bold text-[#ff8c00]">{score}</div>
              <div className="text-xs text-gray-600">Score</div>
            </div>
            <div className="rounded-lg border border-white/60 bg-white/80 p-3 text-center">
              <div className={`text-lg font-semibold ${performanceLevel.tone}`}>{performanceLevel.label}</div>
              <div className="text-xs text-gray-600">Performance</div>
            </div>
          </div>

          <div className="border-t border-gray-200 pt-4">
            <h4 className="text-sm font-semibold text-gray-700 mb-3">Decision timeline</h4>
            <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
              {timeline.length === 0 && (
                <p className="text-xs text-gray-500">Work through the scenario to populate your response timeline.</p>
              )}
              {timeline.map((entry) => (
                <div
                  key={entry.stepId + entry.option.label}
                  className={`rounded border px-3 py-2 text-xs ${
                    entry.option.impact === "ideal"
                      ? "border-emerald-400/60 bg-emerald-50"
                      : entry.option.impact === "acceptable"
                      ? "border-blue-300/60 bg-blue-50"
                      : "border-red-400/60 bg-red-50"
                  }`}
                >
                  <div className="font-semibold text-gray-700 mb-1">{entry.stepPrompt}</div>
                  <div className="text-gray-600 mb-1">{entry.option.label}</div>
                  <div className="text-gray-500">Impact: {entry.option.impact.toUpperCase()}</div>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
