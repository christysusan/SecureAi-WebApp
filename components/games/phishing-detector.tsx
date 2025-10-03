"use client"

import { useState, useEffect } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { Mail, AlertTriangle, CheckCircle, Eye, Shield, Target, Link as LinkIcon, Trophy } from "lucide-react"

// Simple confetti replacement
const triggerConfetti = () => {
  // Simple visual feedback instead of confetti
  console.log("🎉 Correct!")
}

interface Email {
  id: number
  sender: string
  subject: string
  content: string
  isPhishing: boolean
  indicators: string[]
  urgency: 'low' | 'medium' | 'high'
  category: string
}

const phishingEmails: Email[] = [
  {
    id: 1,
    sender: "security@bankng.com",
    subject: "URGENT: Account Suspension - Verify Now!",
    content: `Dear Customer,\n\nYour account has been suspended due to suspicious activity. You must verify your account within 24 hours or it will be permanently closed.\n\nClick here to verify: https://bankng-verify.net/login\n\nBest regards,\nSecurity Team`,
    isPhishing: true,
    indicators: ["Suspicious domain", "Urgent language", "Threatening consequences", "Suspicious link"],
    urgency: 'high',
    category: 'Banking'
  },
  {
    id: 2,
    sender: "notifications@company.com",
    subject: "Weekly Security Report",
    content: `Hi team,\n\nHere's this week's security report:\n\n- 0 security incidents\n- All systems operational\n- Next training: March 15th\n\nPlease review the attached report.\n\nBest,\nIT Security`,
    isPhishing: false,
    indicators: ["Legitimate sender", "Professional tone", "No urgent requests", "Internal communication"],
    urgency: 'low',
    category: 'Corporate'
  },
  {
    id: 3,
    sender: "noreply@microsoft-security.biz",
    subject: "Your Microsoft account sign-in",
    content: `We noticed a new sign-in to your Microsoft account.\n\nLocation: Nigeria\nDevice: Chrome on Windows\n\nIf this wasn't you, please secure your account immediately by clicking below:\n\nhttps://microsoft-secure.biz/account/verify\n\nMicrosoft Security Team`,
    isPhishing: true,
    indicators: ["Fake domain (.biz)", "Suspicious location", "Impersonation", "Fake security alert"],
    urgency: 'high',
    category: 'Tech Support'
  },
  {
    id: 4,
    sender: "admin@yourcompany.com",
    subject: "Password Policy Update",
    content: `Hello everyone,\n\nWe're updating our password policy effective next month:\n\n- Minimum 12 characters\n- Include special characters\n- Change every 90 days\n\nFull details in the employee handbook.\n\nThanks,\nIT Administration`,
    isPhishing: false,
    indicators: ["Internal sender", "Policy information", "No links", "Professional communication"],
    urgency: 'low',
    category: 'Policy'
  },
  {
    id: 5,
    sender: "support@paypal-security.net",
    subject: "Payment Failed - Update Payment Method",
    content: `Your recent payment of $299.99 has failed.\n\nTo avoid service interruption, please update your payment method immediately.\n\nUpdate Payment: https://paypal-security.net/update-payment\n\nReference: PP-89237492847\n\nPayPal Security`,
    isPhishing: true,
    indicators: ["Fake domain", "False payment claim", "Urgency", "Suspicious reference number"],
    urgency: 'high',
    category: 'Payment'
  },
  {
    id: 6,
    sender: "hr@yourcompany.com",
    subject: "Holiday Schedule 2024",
    content: `Team,\n\nPlease find the 2024 holiday schedule below:\n\n- New Year's Day: Jan 1\n- Memorial Day: May 27\n- Independence Day: July 4\n- Labor Day: Sep 2\n- Thanksgiving: Nov 28-29\n- Christmas: Dec 25\n\nHR Department`,
    isPhishing: false,
    indicators: ["Legitimate HR communication", "Standard information", "No urgent requests", "Internal sender"],
    urgency: 'low',
    category: 'HR'
  }
]

export default function PhishingDetectorGame() {
  const [currentEmail, setCurrentEmail] = useState<Email | null>(null)
  const [emailQueue, setEmailQueue] = useState<Email[]>([])
  const [score, setScore] = useState(0)
  const [streak, setStreak] = useState(0)
  const [emailsAnalyzed, setEmailsAnalyzed] = useState(0)
  const [correctlyIdentified, setCorrectlyIdentified] = useState(0)
  const [gameRunning, setGameRunning] = useState(false)
  const [timeLeft, setTimeLeft] = useState(120)
  const [selectedChoice, setSelectedChoice] = useState<'legitimate' | 'phishing' | null>(null)
  const [showResult, setShowResult] = useState(false)
  const [showIndicators, setShowIndicators] = useState(false)
  const [recentEmails, setRecentEmails] = useState<Array<Email & { userChoice: string, correct: boolean }>>([])

  const shuffleEmails = () => {
    const shuffled = [...phishingEmails].sort(() => Math.random() - 0.5)
    setEmailQueue(shuffled)
    setCurrentEmail(shuffled[0])
  }

  const startGame = () => {
    setGameRunning(true)
    setTimeLeft(120)
    setScore(0)
    setStreak(0)
    setEmailsAnalyzed(0)
    setCorrectlyIdentified(0)
    setSelectedChoice(null)
    setShowResult(false)
    setShowIndicators(false)
    setRecentEmails([])
    shuffleEmails()
  }

  const nextEmail = () => {
    if (emailQueue.length > 1) {
      const newQueue = emailQueue.slice(1)
      setEmailQueue(newQueue)
      setCurrentEmail(newQueue[0])
    } else {
      shuffleEmails()
    }
    setSelectedChoice(null)
    setShowResult(false)
    setShowIndicators(false)
  }

  const analyzeEmail = (choice: 'legitimate' | 'phishing') => {
    if (!currentEmail || selectedChoice) return

    setSelectedChoice(choice)
    setEmailsAnalyzed(prev => prev + 1)

    const isCorrect = (choice === 'phishing' && currentEmail.isPhishing) || 
                     (choice === 'legitimate' && !currentEmail.isPhishing)

    if (isCorrect) {
      setCorrectlyIdentified(prev => prev + 1)
      setStreak(prev => prev + 1)
      const points = currentEmail.urgency === 'high' ? 15 : currentEmail.urgency === 'medium' ? 10 : 5
      setScore(prev => prev + points + (streak * 2))
      
      triggerConfetti()
    } else {
      setStreak(0)
    }

    // Add to recent emails
    setRecentEmails(prev => [{
      ...currentEmail,
      userChoice: choice,
      correct: isCorrect
    }, ...prev.slice(0, 4)])

    setShowResult(true)
    
    // Auto advance after 3 seconds
    setTimeout(() => {
      nextEmail()
    }, 3000)
  }

  const getUrgencyColor = (urgency: string) => {
    switch (urgency) {
      case 'high': return 'text-red-500 bg-red-50 border-red-200'
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200'
      default: return 'text-green-600 bg-green-50 border-green-200'
    }
  }

  const getSenderSecurity = (sender: string) => {
    if (sender.includes('security') && !sender.includes('@yourcompany.com')) {
      return { level: 'suspicious', color: 'text-red-500' }
    }
    if (sender.includes('@yourcompany.com')) {
      return { level: 'trusted', color: 'text-green-500' }
    }
    return { level: 'unknown', color: 'text-yellow-500' }
  }

  useEffect(() => {
    let timer: NodeJS.Timeout
    if (gameRunning && timeLeft > 0) {
      timer = setTimeout(() => setTimeLeft(prev => prev - 1), 1000)
    } else if (timeLeft === 0) {
      setGameRunning(false)
    }
    return () => clearTimeout(timer)
  }, [gameRunning, timeLeft])

  const accuracy = emailsAnalyzed > 0 ? Math.round((correctlyIdentified / emailsAnalyzed) * 100) : 0

  if (!gameRunning && timeLeft > 0) {
    return (
      <div className="max-w-4xl mx-auto p-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center"
        >
          <h1 className="text-3xl font-bold text-[#ff8c00] mb-4 flex items-center justify-center gap-3">
            <Mail className="w-8 h-8" />
            📧 Phishing Detective
            <Shield className="w-8 h-8" />
          </h1>
          <p className="text-gray-600 mb-8">Analyze emails to identify phishing attempts and protect your organization!</p>
          
          <div className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg p-8 border-2 border-[#ff8c00] max-w-2xl mx-auto">
            <h2 className="text-xl font-semibold mb-4">How to Play</h2>
            <div className="text-left space-y-3 text-gray-700">
              <div className="flex items-start gap-3">
                <Eye className="w-5 h-5 text-[#ff8c00] mt-0.5" />
                <p>Carefully read each email and look for suspicious indicators</p>
              </div>
              <div className="flex items-start gap-3">
                <Target className="w-5 h-5 text-[#ff8c00] mt-0.5" />
                <p>Decide if the email is legitimate or a phishing attempt</p>
              </div>
              <div className="flex items-start gap-3">
                <Trophy className="w-5 h-5 text-[#ff8c00] mt-0.5" />
                <p>Score points for correct identifications and build streaks</p>
              </div>
            </div>
            
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={startGame}
              className="mt-6 px-8 py-3 bg-[#ff8c00] text-white rounded-lg font-medium hover:bg-[#ff6b35] transition-colors"
            >
              Start Phishing Detection
            </motion.button>
          </div>
        </motion.div>
      </div>
    )
  }

  return (
    <div className="max-w-7xl mx-auto p-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center mb-6"
      >
        <h1 className="text-3xl font-bold text-[#ff8c00] mb-2 flex items-center justify-center gap-3">
          <Mail className="w-8 h-8" />
          📧 Phishing Detective
          <Shield className="w-8 h-8" />
        </h1>
      </motion.div>

      <div className="grid lg:grid-cols-4 gap-6">
        {/* Stats Panel */}
        <motion.div 
          initial={{ x: -20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg p-6 border-2 border-[#ff8c00]"
        >
          <h2 className="text-lg font-semibold text-[#ff8c00] mb-4">Detective Stats</h2>
          
          <div className="space-y-4">
            <div className="text-center p-3 bg-white/50 rounded-lg">
              <div className="text-2xl font-bold text-[#ff8c00]">{score}</div>
              <div className="text-sm text-gray-600">Score</div>
            </div>
            
            <div className="text-center p-3 bg-white/50 rounded-lg">
              <div className="text-2xl font-bold text-green-600">{streak}</div>
              <div className="text-sm text-gray-600">Streak</div>
            </div>
            
            <div className="text-center p-3 bg-white/50 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">{accuracy}%</div>
              <div className="text-sm text-gray-600">Accuracy</div>
            </div>
            
            <div className="text-center p-3 bg-white/50 rounded-lg">
              <div className="text-2xl font-bold text-purple-600">{timeLeft}s</div>
              <div className="text-sm text-gray-600">Time Left</div>
            </div>
          </div>

          {/* Recent Results */}
          <div className="mt-6">
            <h3 className="font-medium text-gray-700 mb-2">Recent Analysis</h3>
            <div className="space-y-1">
              {recentEmails.map((email, index) => (
                <div 
                  key={`${email.id}-${index}`}
                  className={`text-xs p-2 rounded flex items-center gap-2 ${
                    email.correct ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                  }`}
                >
                  {email.correct ? (
                    <CheckCircle className="w-3 h-3" />
                  ) : (
                    <AlertTriangle className="w-3 h-3" />
                  )}
                  <span className="truncate">{email.subject}</span>
                </div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* Email Display */}
        <motion.div 
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          className="lg:col-span-2 bg-white rounded-lg p-6 border-2 border-gray-200 shadow-lg"
        >
          {currentEmail && (
            <>
              <div className="border-b pb-4 mb-4">
                <div className="flex items-center justify-between mb-2">
                  <h2 className="text-lg font-semibold">Email Analysis</h2>
                  <span className={`px-2 py-1 text-xs rounded border ${getUrgencyColor(currentEmail.urgency)}`}>
                    {currentEmail.urgency.toUpperCase()} PRIORITY
                  </span>
                </div>
                
                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-2">
                    <strong>From:</strong> 
                    <span className={getSenderSecurity(currentEmail.sender).color}>
                      {currentEmail.sender}
                    </span>
                    <span className={`px-1 py-0.5 text-xs rounded ${getSenderSecurity(currentEmail.sender).color.replace('text-', 'bg-').replace('500', '100')}`}>
                      {getSenderSecurity(currentEmail.sender).level}
                    </span>
                  </div>
                  <div><strong>Subject:</strong> {currentEmail.subject}</div>
                  <div className="flex items-center gap-2">
                    <strong>Category:</strong> 
                    <span className="px-2 py-1 bg-gray-100 text-gray-700 text-xs rounded">
                      {currentEmail.category}
                    </span>
                  </div>
                </div>
              </div>

              <div className="bg-gray-50 rounded-lg p-4 mb-4">
                <pre className="whitespace-pre-wrap text-sm text-gray-800 font-mono">
                  {currentEmail.content}
                </pre>
              </div>

              <div className="flex items-center gap-2 mb-4">
                <button
                  onClick={() => setShowIndicators(!showIndicators)}
                  className="flex items-center gap-2 px-3 py-1 bg-gray-100 hover:bg-gray-200 rounded text-sm transition-colors"
                >
                  <Eye className="w-4 h-4" />
                  {showIndicators ? 'Hide' : 'Show'} Security Indicators
                </button>
                
                {currentEmail.content.includes('http') && (
                  <span className="flex items-center gap-1 text-xs text-orange-600">
                    <LinkIcon className="w-3 h-3" />
                    Contains Links
                  </span>
                )}
              </div>

              <AnimatePresence>
                {showIndicators && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mb-4 p-3 bg-blue-50 rounded-lg border border-blue-200"
                  >
                    <h4 className="font-medium text-blue-800 mb-2">Security Indicators:</h4>
                    <ul className="text-sm text-blue-700 space-y-1">
                      {currentEmail.indicators.map((indicator, index) => (
                        <li key={index} className="flex items-center gap-2">
                          <div className="w-1.5 h-1.5 bg-blue-500 rounded-full"></div>
                          {indicator}
                        </li>
                      ))}
                    </ul>
                  </motion.div>
                )}
              </AnimatePresence>

              <div className="flex gap-4">
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={() => analyzeEmail('legitimate')}
                  disabled={selectedChoice !== null}
                  className={`flex-1 py-3 px-4 rounded-lg font-medium transition-colors ${
                    selectedChoice === 'legitimate'
                      ? currentEmail.isPhishing
                        ? 'bg-red-500 text-white'
                        : 'bg-green-500 text-white'
                      : 'bg-green-100 hover:bg-green-200 text-green-800 disabled:opacity-50'
                  }`}
                >
                  <CheckCircle className="w-5 h-5 inline mr-2" />
                  Legitimate Email
                </motion.button>

                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={() => analyzeEmail('phishing')}
                  disabled={selectedChoice !== null}
                  className={`flex-1 py-3 px-4 rounded-lg font-medium transition-colors ${
                    selectedChoice === 'phishing'
                      ? currentEmail.isPhishing
                        ? 'bg-green-500 text-white'
                        : 'bg-red-500 text-white'
                      : 'bg-red-100 hover:bg-red-200 text-red-800 disabled:opacity-50'
                  }`}
                >
                  <AlertTriangle className="w-5 h-5 inline mr-2" />
                  Phishing Attempt
                </motion.button>
              </div>

              <AnimatePresence>
                {showResult && selectedChoice && (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={`mt-4 p-4 rounded-lg border-2 ${
                      (selectedChoice === 'phishing' && currentEmail.isPhishing) ||
                      (selectedChoice === 'legitimate' && !currentEmail.isPhishing)
                        ? 'bg-green-50 border-green-200'
                        : 'bg-red-50 border-red-200'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      {(selectedChoice === 'phishing' && currentEmail.isPhishing) ||
                       (selectedChoice === 'legitimate' && !currentEmail.isPhishing) ? (
                        <CheckCircle className="w-5 h-5 text-green-600" />
                      ) : (
                        <AlertTriangle className="w-5 h-5 text-red-600" />
                      )}
                      <span className="font-medium">
                        {(selectedChoice === 'phishing' && currentEmail.isPhishing) ||
                         (selectedChoice === 'legitimate' && !currentEmail.isPhishing)
                          ? 'Correct Analysis!'
                          : 'Incorrect Analysis'}
                      </span>
                    </div>
                    <p className="text-sm text-gray-700">
                      This email is actually {currentEmail.isPhishing ? 'a phishing attempt' : 'legitimate'}.
                      {currentEmail.isPhishing && (
                        <span className="block mt-1 font-medium text-red-600">
                          ⚠️ Key indicators: {currentEmail.indicators.slice(0, 2).join(', ')}
                        </span>
                      )}
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>
            </>
          )}
        </motion.div>

        {/* Tips Panel */}
        <motion.div 
          initial={{ x: 20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          className="bg-gradient-to-br from-orange-50 to-red-50 rounded-lg p-6 border-2 border-orange-200"
        >
          <h2 className="text-lg font-semibold text-orange-700 mb-4">Phishing Detection Tips</h2>
          
          <div className="space-y-4 text-sm text-gray-700">
            <div>
              <h4 className="font-medium text-red-600 mb-1">🚨 Red Flags:</h4>
              <ul className="space-y-1 text-xs">
                <li>• Urgent/threatening language</li>
                <li>• Suspicious domains</li>
                <li>• Generic greetings</li>
                <li>• Spelling errors</li>
                <li>• Unexpected attachments</li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-medium text-green-600 mb-1">✅ Good Signs:</h4>
              <ul className="space-y-1 text-xs">
                <li>• Known sender domain</li>
                <li>• Professional language</li>
                <li>• No urgent requests</li>
                <li>• Expected communication</li>
                <li>• Proper formatting</li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-medium text-blue-600 mb-1">🔍 Always Check:</h4>
              <ul className="space-y-1 text-xs">
                <li>• Sender email address</li>
                <li>• Link destinations</li>
                <li>• Urgency level</li>
                <li>• Request legitimacy</li>
                <li>• Context relevance</li>
              </ul>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Game Over Modal */}
      <AnimatePresence>
        {!gameRunning && timeLeft === 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white rounded-lg p-8 max-w-md w-full mx-4"
            >
              <h2 className="text-2xl font-bold text-center mb-4">Detective Report</h2>
              <div className="text-center space-y-2">
                <p>Final Score: <span className="font-bold text-[#ff8c00]">{score}</span></p>
                <p>Emails Analyzed: <span className="font-bold">{emailsAnalyzed}</span></p>
                <p>Correctly Identified: <span className="font-bold text-green-600">{correctlyIdentified}</span></p>
                <p>Accuracy: <span className="font-bold text-blue-600">{accuracy}%</span></p>
                <p>Best Streak: <span className="font-bold text-purple-600">{streak}</span></p>
              </div>
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={startGame}
                className="w-full mt-6 py-2 bg-[#ff8c00] text-white rounded-lg font-medium hover:bg-[#ff6b35] transition-colors"
              >
                Play Again
              </motion.button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}