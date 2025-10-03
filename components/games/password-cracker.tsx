"use client"

import { useState, useEffect, useRef } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { Shield, AlertTriangle, CheckCircle, Clock, Zap, Lock, Unlock } from "lucide-react"

interface AttackAttempt {
  id: number
  password: string
  method: string
  time: number
  success: boolean
}

const ATTACK_METHODS = [
  { name: "Dictionary", speed: 1000, description: "Common passwords" },
  { name: "Brute Force", speed: 500, description: "All combinations" },
  { name: "Rainbow Table", speed: 750, description: "Pre-computed hashes" },
  { name: "Social Engineering", speed: 2000, description: "Personal info" }
]

const COMMON_PASSWORDS = [
  "password", "123456", "password123", "admin", "qwerty", 
  "letmein", "welcome", "monkey", "dragon", "master"
]

const PASSWORD_PATTERNS = [
  "john1985", "sarah@gmail", "company123", "birthday1990", "pet_name"
]

export default function PasswordCrackerGame() {
  const [currentPassword, setCurrentPassword] = useState('')
  const [attacksBlocked, setAttacksBlocked] = useState(0)
  const [attacksSuccessful, setAttacksSuccessful] = useState(0)
  const [gameRunning, setGameRunning] = useState(false)
  const [timeLeft, setTimeLeft] = useState(60)
  const [currentAttack, setCurrentAttack] = useState<AttackAttempt | null>(null)
  const [attackHistory, setAttackHistory] = useState<AttackAttempt[]>([])
  const [attackProgress, setAttackProgress] = useState(0)
  const [passwordStrength, setPasswordStrength] = useState(0)
  const [strengthFeedback, setStrengthFeedback] = useState('')
  
  const attackTimeoutRef = useRef<NodeJS.Timeout>()
  const gameTimerRef = useRef<NodeJS.Timeout>()

  const calculatePasswordStrength = (password: string) => {
  let strength = 0
  const feedback: string[] = []

    if (password.length >= 8) {
      strength += 20
    } else {
      feedback.push("Use at least 8 characters")
    }

    if (password.length >= 12) {
      strength += 15
    }

    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) {
      strength += 20
    } else {
      feedback.push("Mix uppercase and lowercase")
    }

    if (/\d/.test(password)) {
      strength += 15
    } else {
      feedback.push("Include numbers")
    }

    if (/[^a-zA-Z0-9]/.test(password)) {
      strength += 20
    } else {
      feedback.push("Add special characters")
    }

    if (!COMMON_PASSWORDS.some(common => password.toLowerCase().includes(common.toLowerCase()))) {
      strength += 10
    } else {
      feedback.push("Avoid common passwords")
    }

    setPasswordStrength(Math.min(strength, 100))
    setStrengthFeedback(feedback.join(", "))
  }

  const generateAttack = () => {
    const method = ATTACK_METHODS[Math.floor(Math.random() * ATTACK_METHODS.length)]
    let targetPassword = ""
    
    if (method.name === "Dictionary") {
      targetPassword = COMMON_PASSWORDS[Math.floor(Math.random() * COMMON_PASSWORDS.length)]
    } else if (method.name === "Social Engineering") {
      targetPassword = PASSWORD_PATTERNS[Math.floor(Math.random() * PASSWORD_PATTERNS.length)]
    } else {
      // Generate random password attempt
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
      targetPassword = Array.from({length: Math.floor(Math.random() * 8) + 4}, () => 
        chars[Math.floor(Math.random() * chars.length)]
      ).join('')
    }

    const attack: AttackAttempt = {
      id: Date.now(),
      password: targetPassword,
      method: method.name,
      time: method.speed,
      success: false
    }

    return attack
  }

  const executeAttack = (attack: AttackAttempt) => {
    setCurrentAttack(attack)
    setAttackProgress(0)

    // Simulate attack progress
    const progressInterval = setInterval(() => {
      setAttackProgress(prev => {
        if (prev >= 100) {
          clearInterval(progressInterval)
          completeAttack(attack)
          return 100
        }
        return prev + (100 / (attack.time / 100))
      })
    }, 100)

    return progressInterval
  }

  const completeAttack = (attack: AttackAttempt) => {
    // Determine if attack succeeds based on password strength and method
    let successChance = 0

    if (currentPassword === attack.password) {
      successChance = 90 // Direct match
    } else if (attack.method === "Dictionary" && COMMON_PASSWORDS.some(p => 
      currentPassword.toLowerCase().includes(p.toLowerCase())
    )) {
      successChance = 70
    } else if (passwordStrength < 30) {
      successChance = 60
    } else if (passwordStrength < 60) {
      successChance = 30
    } else if (passwordStrength < 80) {
      successChance = 15
    } else {
      successChance = 5
    }

    const success = Math.random() * 100 < successChance
    
    const completedAttack = { ...attack, success }
    
    if (success) {
      setAttacksSuccessful(prev => prev + 1)
    } else {
      setAttacksBlocked(prev => prev + 1)
    }

    setAttackHistory(prev => [completedAttack, ...prev.slice(0, 9)])
    setCurrentAttack(null)
    setAttackProgress(0)

    // Schedule next attack
    if (gameRunning) {
      attackTimeoutRef.current = setTimeout(() => {
        const nextAttack = generateAttack()
        executeAttack(nextAttack)
      }, 2000 + Math.random() * 3000)
    }
  }

  const startGame = () => {
    setGameRunning(true)
    setTimeLeft(60)
    setAttacksBlocked(0)
    setAttacksSuccessful(0)
    setAttackHistory([])
    setCurrentAttack(null)
    setAttackProgress(0)

    // Start first attack
    const firstAttack = generateAttack()
    executeAttack(firstAttack)

    // Start game timer
    gameTimerRef.current = setInterval(() => {
      setTimeLeft(prev => {
        if (prev <= 1) {
          endGame()
          return 0
        }
        return prev - 1
      })
    }, 1000)
  }

  const endGame = () => {
    setGameRunning(false)
    if (attackTimeoutRef.current) clearTimeout(attackTimeoutRef.current)
    if (gameTimerRef.current) clearInterval(gameTimerRef.current)
    setCurrentAttack(null)
  }

  const upgradePassword = () => {
    const upgrades = [
      (pwd: string) => pwd + Math.floor(Math.random() * 100),
      (pwd: string) => pwd + "!@#"[Math.floor(Math.random() * 3)],
      (pwd: string) => pwd.charAt(0).toUpperCase() + pwd.slice(1),
      (pwd: string) => pwd.replace(/[aeiou]/g, c => c.toUpperCase())
    ]
    
    const upgrade = upgrades[Math.floor(Math.random() * upgrades.length)]
    setCurrentPassword(upgrade(currentPassword))
  }

  useEffect(() => {
    calculatePasswordStrength(currentPassword)
  }, [currentPassword])

  useEffect(() => {
    return () => {
      if (attackTimeoutRef.current) clearTimeout(attackTimeoutRef.current)
      if (gameTimerRef.current) clearInterval(gameTimerRef.current)
    }
  }, [])

  const getStrengthColor = () => {
    if (passwordStrength < 30) return 'text-red-500'
    if (passwordStrength < 60) return 'text-yellow-500'
    if (passwordStrength < 80) return 'text-blue-500'
    return 'text-green-500'
  }

  const getStrengthBg = () => {
    if (passwordStrength < 30) return 'bg-red-500'
    if (passwordStrength < 60) return 'bg-yellow-500'
    if (passwordStrength < 80) return 'bg-blue-500'
    return 'bg-green-500'
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center mb-6"
      >
        <h1 className="text-3xl font-bold text-[#ff8c00] mb-2 flex items-center justify-center gap-3">
          <Shield className="w-8 h-8" />
          🔐 Password Defense Challenge
          <Lock className="w-8 h-8" />
        </h1>
        <p className="text-gray-600">Defend against password attacks by creating stronger passwords!</p>
      </motion.div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Password Setup */}
        <motion.div 
          initial={{ x: -20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg p-6 border-2 border-[#ff8c00]"
        >
          <h2 className="text-xl font-semibold text-[#ff8c00] mb-4 flex items-center gap-2">
            <Lock className="w-5 h-5" />
            Password Defense
          </h2>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Your Password
              </label>
              <input
                type="text"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Enter a strong password..."
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#ff8c00] focus:border-[#ff8c00]"
                disabled={gameRunning}
              />
            </div>

            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Password Strength</span>
                <span className={`font-medium ${getStrengthColor()}`}>
                  {passwordStrength}%
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${passwordStrength}%` }}
                  className={`h-2 rounded-full ${getStrengthBg()}`}
                  transition={{ duration: 0.5 }}
                />
              </div>
              {strengthFeedback && (
                <p className="text-xs text-gray-600 mt-1">{strengthFeedback}</p>
              )}
            </div>

            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={upgradePassword}
              disabled={gameRunning || !currentPassword}
              className="w-full py-2 bg-[#ffa500] text-white rounded-lg font-medium hover:bg-[#ff8c00] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Zap className="w-4 h-4 inline mr-2" />
              Quick Upgrade
            </motion.button>

            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={gameRunning ? endGame : startGame}
              disabled={!currentPassword}
              className={`w-full py-2 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                gameRunning 
                  ? 'bg-red-500 hover:bg-red-600 text-white' 
                  : 'bg-[#ff8c00] hover:bg-[#ff6b35] text-white'
              }`}
            >
              {gameRunning ? 'Stop Defense' : 'Start Defense'}
            </motion.button>
          </div>
        </motion.div>

        {/* Attack Monitor */}
        <motion.div 
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          className="bg-gradient-to-br from-red-50 to-pink-50 rounded-lg p-6 border-2 border-red-300"
        >
          <h2 className="text-xl font-semibold text-red-600 mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" />
            Attack Monitor
          </h2>

          {gameRunning && (
            <div className="mb-4 text-center">
              <div className="text-2xl font-bold text-[#ff8c00] flex items-center justify-center gap-2">
                <Clock className="w-6 h-6" />
                {timeLeft}s
              </div>
              <p className="text-sm text-gray-600">Time Remaining</p>
            </div>
          )}

          <AnimatePresence>
            {currentAttack && (
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.9 }}
                className="bg-white rounded-lg p-4 border border-red-200 mb-4"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-red-600">
                    {currentAttack.method} Attack
                  </span>
                  <span className="text-sm text-gray-500">
                    {attackProgress.toFixed(0)}%
                  </span>
                </div>
                
                <div className="w-full bg-gray-200 rounded-full h-2 mb-2">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${attackProgress}%` }}
                    className="h-2 bg-red-500 rounded-full"
                  />
                </div>
                
                <p className="text-xs text-gray-600">
                  Target: {currentAttack.password}
                </p>
                <p className="text-xs text-gray-500">
                  Method: {ATTACK_METHODS.find(m => m.name === currentAttack.method)?.description}
                </p>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="grid grid-cols-2 gap-3">
            <div className="text-center p-3 bg-green-100 rounded-lg">
              <div className="text-xl font-bold text-green-600">{attacksBlocked}</div>
              <div className="text-xs text-green-700">Blocked</div>
            </div>
            <div className="text-center p-3 bg-red-100 rounded-lg">
              <div className="text-xl font-bold text-red-600">{attacksSuccessful}</div>
              <div className="text-xs text-red-700">Successful</div>
            </div>
          </div>
        </motion.div>

        {/* Attack History */}
        <motion.div 
          initial={{ x: 20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          className="bg-gradient-to-br from-gray-50 to-slate-50 rounded-lg p-6 border-2 border-gray-300"
        >
          <h2 className="text-xl font-semibold text-gray-700 mb-4">Attack History</h2>
          
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {attackHistory.map((attack) => (
              <motion.div
                key={attack.id}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                className={`p-3 rounded-lg border ${
                  attack.success 
                    ? 'bg-red-50 border-red-200' 
                    : 'bg-green-50 border-green-200'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-sm">
                    {attack.method}
                  </span>
                  {attack.success ? (
                    <Unlock className="w-4 h-4 text-red-500" />
                  ) : (
                    <CheckCircle className="w-4 h-4 text-green-500" />
                  )}
                </div>
                <p className="text-xs text-gray-600 mt-1">
                  Target: {attack.password}
                </p>
                <p className={`text-xs font-medium ${
                  attack.success ? 'text-red-600' : 'text-green-600'
                }`}>
                  {attack.success ? 'BREACHED' : 'BLOCKED'}
                </p>
              </motion.div>
            ))}
            {attackHistory.length === 0 && (
              <p className="text-gray-500 text-sm text-center py-8">
                No attacks yet. Start the defense to begin monitoring.
              </p>
            )}
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
              <h2 className="text-2xl font-bold text-center mb-4">Defense Complete!</h2>
              <div className="text-center space-y-2">
                <p>Password Strength: <span className={`font-bold ${getStrengthColor()}`}>{passwordStrength}%</span></p>
                <p>Attacks Blocked: <span className="font-bold text-green-600">{attacksBlocked}</span></p>
                <p>Attacks Successful: <span className="font-bold text-red-600">{attacksSuccessful}</span></p>
                <p>Success Rate: <span className="font-bold text-[#ff8c00]">
                  {attacksBlocked + attacksSuccessful > 0 
                    ? Math.round((attacksBlocked / (attacksBlocked + attacksSuccessful)) * 100)
                    : 0}%
                </span></p>
              </div>
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setTimeLeft(60)}
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