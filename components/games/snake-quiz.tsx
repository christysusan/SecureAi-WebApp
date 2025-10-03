"use client"

import { useState, useEffect, useRef, useCallback } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { Play, Pause, RotateCcw, Trophy, Brain, Target } from "lucide-react"

// Simple confetti replacement
const triggerConfetti = () => {
  console.log("🎉 Correct answer!")
}

interface Position {
  x: number
  y: number
}

interface Question {
  question: string
  options: string[]
  correct: number
  explanation: string
  category: string
}

const GRID_SIZE = 20
const INITIAL_SNAKE = [{ x: 10, y: 10 }]
const INITIAL_DIRECTION = { x: 1, y: 0 }

const questions: Question[] = [
  {
    question: "What is SQL injection primarily caused by?",
    options: [
      "Weak passwords",
      "Unvalidated user input",
      "Missing HTTPS",
      "Poor UI design"
    ],
    correct: 1,
    explanation: "SQL injection occurs when user input is not properly validated or sanitized, allowing attackers to insert malicious SQL code.",
    category: "Web Security"
  },
  {
    question: "Which encryption algorithm is considered quantum-resistant?",
    options: [
      "AES-256",
      "RSA-2048", 
      "Lattice-based cryptography",
      "MD5"
    ],
    correct: 2,
    explanation: "Lattice-based cryptography is designed to be secure against quantum computer attacks, unlike traditional public-key cryptography.",
    category: "Cryptography"
  },
  {
    question: "What does CSRF stand for?",
    options: [
      "Cross-Site Request Forgery",
      "Cross-Site Resource Failure", 
      "Client-Side Request Format",
      "Cascading Style Request Form"
    ],
    correct: 0,
    explanation: "CSRF (Cross-Site Request Forgery) is an attack that forces users to execute unwanted actions on a web application.",
    category: "Web Security"
  },
  {
    question: "Which principle of least privilege applies to?",
    options: [
      "Only network access",
      "Only file permissions",
      "All system access controls",
      "Only database access"
    ],
    correct: 2,
    explanation: "Principle of least privilege should be applied to all system access controls, granting minimum necessary permissions.",
    category: "Access Control"
  },
  {
    question: "What is the main purpose of a honeypot?",
    options: [
      "Store sensitive data",
      "Detect and analyze attacks",
      "Encrypt communications",
      "Backup systems"
    ],
    correct: 1,
    explanation: "Honeypots are decoy systems designed to attract, detect, and analyze malicious activity and attack patterns.",
    category: "Network Security"
  }
]

export default function SnakeQuiz() {
  const [snake, setSnake] = useState<Position[]>(INITIAL_SNAKE)
  const [direction, setDirection] = useState<Position>(INITIAL_DIRECTION)
  const [food, setFood] = useState<Position>({ x: 15, y: 15 })
  const [gameOver, setGameOver] = useState(false)
  const [gameRunning, setGameRunning] = useState(false)
  const [score, setScore] = useState(0)
  const [currentQuestion, setCurrentQuestion] = useState<Question | null>(null)
  const [showQuestion, setShowQuestion] = useState(false)
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null)
  const [showExplanation, setShowExplanation] = useState(false)
  const [questionsAnswered, setQuestionsAnswered] = useState(0)
  const [correctAnswers, setCorrectAnswers] = useState(0)
  
  const gameLoopRef = useRef<NodeJS.Timeout>()
  const canvasRef = useRef<HTMLCanvasElement>(null)

  const generateFood = useCallback((currentSnake: Position[]) => {
    let newFood: Position
    do {
      newFood = {
        x: Math.floor(Math.random() * GRID_SIZE),
        y: Math.floor(Math.random() * GRID_SIZE)
      }
    } while (currentSnake.some(segment => segment.x === newFood.x && segment.y === newFood.y))
    return newFood
  }, [])

  const triggerQuestion = useCallback(() => {
    const randomQuestion = questions[Math.floor(Math.random() * questions.length)]
    setCurrentQuestion(randomQuestion)
    setShowQuestion(true)
    setGameRunning(false)
    setSelectedAnswer(null)
    setShowExplanation(false)
  }, [])

  const checkCollision = useCallback((head: Position, body: Position[]) => {
    // Wall collision
    if (head.x < 0 || head.x >= GRID_SIZE || head.y < 0 || head.y >= GRID_SIZE) {
      return true
    }
    // Self collision
    return body.some(segment => segment.x === head.x && segment.y === head.y)
  }, [])

  const moveSnake = useCallback(() => {
    if (!gameRunning || gameOver) return

    setSnake(currentSnake => {
      const newSnake = [...currentSnake]
      const head = { ...newSnake[0] }
      head.x += direction.x
      head.y += direction.y

      if (checkCollision(head, newSnake)) {
        setGameOver(true)
        setGameRunning(false)
        return currentSnake
      }

      newSnake.unshift(head)

      // Check if food is eaten
      if (head.x === food.x && head.y === food.y) {
        setScore(prev => prev + 10)
        setFood(generateFood(newSnake))
        triggerQuestion()
      } else {
        newSnake.pop()
      }

      return newSnake
    })
  }, [direction, food, gameRunning, gameOver, checkCollision, generateFood, triggerQuestion])

  useEffect(() => {
    if (gameRunning && !gameOver) {
      gameLoopRef.current = setInterval(moveSnake, 150)
    } else {
      if (gameLoopRef.current) {
        clearInterval(gameLoopRef.current)
      }
    }

    return () => {
      if (gameLoopRef.current) {
        clearInterval(gameLoopRef.current)
      }
    }
  }, [gameRunning, gameOver, moveSnake])

  useEffect(() => {
    const handleKeyPress = (e: KeyboardEvent) => {
      if (!gameRunning || showQuestion) return

      switch (e.key) {
        case 'ArrowUp':
          if (direction.y === 0) setDirection({ x: 0, y: -1 })
          break
        case 'ArrowDown':
          if (direction.y === 0) setDirection({ x: 0, y: 1 })
          break
        case 'ArrowLeft':
          if (direction.x === 0) setDirection({ x: -1, y: 0 })
          break
        case 'ArrowRight':
          if (direction.x === 0) setDirection({ x: 1, y: 0 })
          break
      }
    }

    window.addEventListener('keydown', handleKeyPress)
    return () => window.removeEventListener('keydown', handleKeyPress)
  }, [direction, gameRunning, showQuestion])

  const drawGame = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const cellSize = canvas.width / GRID_SIZE

    // Clear canvas
    ctx.fillStyle = '#1a1a1a'
    ctx.fillRect(0, 0, canvas.width, canvas.height)

    // Draw grid
    ctx.strokeStyle = '#333'
    ctx.lineWidth = 1
    for (let i = 0; i <= GRID_SIZE; i++) {
      ctx.beginPath()
      ctx.moveTo(i * cellSize, 0)
      ctx.lineTo(i * cellSize, canvas.height)
      ctx.stroke()
      
      ctx.beginPath()
      ctx.moveTo(0, i * cellSize)
      ctx.lineTo(canvas.width, i * cellSize)
      ctx.stroke()
    }

    // Draw snake
    snake.forEach((segment, index) => {
      const gradient = ctx.createLinearGradient(
        segment.x * cellSize,
        segment.y * cellSize,
        (segment.x + 1) * cellSize,
        (segment.y + 1) * cellSize
      )
      
      if (index === 0) {
        // Head
        gradient.addColorStop(0, '#ff8c00')
        gradient.addColorStop(1, '#ff6b35')
      } else {
        // Body
        gradient.addColorStop(0, '#ffa500')
        gradient.addColorStop(1, '#ff8c00')
      }
      
      ctx.fillStyle = gradient
      ctx.fillRect(
        segment.x * cellSize + 2,
        segment.y * cellSize + 2,
        cellSize - 4,
        cellSize - 4
      )
      
      // Add glow effect
      ctx.shadowColor = '#ff8c00'
      ctx.shadowBlur = 10
      ctx.fillRect(
        segment.x * cellSize + 2,
        segment.y * cellSize + 2,
        cellSize - 4,
        cellSize - 4
      )
      ctx.shadowBlur = 0
    })

    // Draw food
    const foodGradient = ctx.createRadialGradient(
      food.x * cellSize + cellSize / 2,
      food.y * cellSize + cellSize / 2,
      0,
      food.x * cellSize + cellSize / 2,
      food.y * cellSize + cellSize / 2,
      cellSize / 2
    )
    foodGradient.addColorStop(0, '#ffd700')
    foodGradient.addColorStop(1, '#ff8c00')
    
    ctx.fillStyle = foodGradient
    ctx.beginPath()
    ctx.arc(
      food.x * cellSize + cellSize / 2,
      food.y * cellSize + cellSize / 2,
      cellSize / 2 - 3,
      0,
      2 * Math.PI
    )
    ctx.fill()
    
    // Add pulsing effect to food
    ctx.shadowColor = '#ffd700'
    ctx.shadowBlur = 15
    ctx.fill()
    ctx.shadowBlur = 0
  }, [snake, food])

  useEffect(() => {
    drawGame()
  }, [drawGame])

  const startGame = () => {
    setSnake(INITIAL_SNAKE)
    setDirection(INITIAL_DIRECTION)
    setFood(generateFood(INITIAL_SNAKE))
    setGameOver(false)
    setGameRunning(true)
    setScore(0)
    setQuestionsAnswered(0)
    setCorrectAnswers(0)
    setShowQuestion(false)
    setCurrentQuestion(null)
  }

  const pauseGame = () => {
    setGameRunning(!gameRunning)
  }

  const handleAnswerSelect = (answerIndex: number) => {
    setSelectedAnswer(answerIndex)
    setQuestionsAnswered(prev => prev + 1)
    
    if (answerIndex === currentQuestion?.correct) {
      setCorrectAnswers(prev => prev + 1)
      setScore(prev => prev + 25)
      triggerConfetti()
    }
    
    setShowExplanation(true)
  }

  const continueGame = () => {
    setShowQuestion(false)
    setGameRunning(true)
  }

  const accuracy = questionsAnswered > 0 ? Math.round((correctAnswers / questionsAnswered) * 100) : 0

  return (
    <div className="max-w-6xl mx-auto p-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center mb-6"
      >
        <h1 className="text-3xl font-bold text-[#ff8c00] mb-2 flex items-center justify-center gap-3">
          <Brain className="w-8 h-8" />
          🐍 CyberSnake Quiz
          <Target className="w-8 h-8" />
        </h1>
        <p className="text-gray-600">Eat food to grow your snake and answer cybersecurity questions!</p>
      </motion.div>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Game Canvas */}
        <motion.div 
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="bg-gradient-to-br from-gray-900 to-gray-800 rounded-lg p-4 border-2 border-[#ff8c00]"
        >
          <div className="flex justify-between items-center mb-4">
            <div className="flex gap-4 text-white">
              <span className="flex items-center gap-2">
                <Trophy className="w-4 h-4 text-[#ffd700]" />
                Score: {score}
              </span>
              <span>Length: {snake.length}</span>
            </div>
            <div className="flex gap-2">
              {!gameRunning && !gameOver && (
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={startGame}
                  className="flex items-center gap-2 px-4 py-2 bg-[#ff8c00] text-white rounded-lg font-medium hover:bg-[#ff6b35] transition-colors"
                >
                  <Play className="w-4 h-4" />
                  Start
                </motion.button>
              )}
              {gameRunning && (
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={pauseGame}
                  className="flex items-center gap-2 px-4 py-2 bg-[#ffa500] text-white rounded-lg font-medium hover:bg-[#ff8c00] transition-colors"
                >
                  <Pause className="w-4 h-4" />
                  Pause
                </motion.button>
              )}
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={startGame}
                className="flex items-center gap-2 px-4 py-2 bg-gray-600 text-white rounded-lg font-medium hover:bg-gray-700 transition-colors"
              >
                <RotateCcw className="w-4 h-4" />
                Reset
              </motion.button>
            </div>
          </div>
          
          <canvas
            ref={canvasRef}
            width={400}
            height={400}
            className="border border-gray-600 rounded w-full max-w-md mx-auto"
            style={{ imageRendering: 'pixelated' }}
          />
          
          {gameOver && (
            <motion.div
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center mt-4 p-4 bg-red-900/50 rounded-lg border border-red-600"
            >
              <h2 className="text-xl font-bold text-red-400 mb-2">Game Over!</h2>
              <p className="text-gray-300">Final Score: {score}</p>
              <p className="text-gray-300">Questions Answered: {questionsAnswered}</p>
              <p className="text-gray-300">Accuracy: {accuracy}%</p>
            </motion.div>
          )}
          
          <div className="mt-4 text-center text-gray-400 text-sm">
            Use arrow keys to move • Eat food to grow and answer questions
          </div>
        </motion.div>

        {/* Stats and Question Panel */}
        <div className="space-y-4">
          {/* Stats */}
          <motion.div 
            initial={{ x: 20, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            className="bg-gradient-to-r from-[#ff8c00]/10 to-[#ffa500]/10 rounded-lg p-4 border border-[#ff8c00]/20"
          >
            <h3 className="text-lg font-semibold text-[#ff8c00] mb-3 flex items-center gap-2">
              <Trophy className="w-5 h-5" />
              Game Statistics
            </h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center p-3 bg-white/5 rounded-lg">
                <div className="text-2xl font-bold text-[#ff8c00]">{score}</div>
                <div className="text-sm text-gray-600">Total Score</div>
              </div>
              <div className="text-center p-3 bg-white/5 rounded-lg">
                <div className="text-2xl font-bold text-[#ffa500]">{questionsAnswered}</div>
                <div className="text-sm text-gray-600">Questions</div>
              </div>
              <div className="text-center p-3 bg-white/5 rounded-lg">
                <div className="text-2xl font-bold text-[#ffd700]">{correctAnswers}</div>
                <div className="text-sm text-gray-600">Correct</div>
              </div>
              <div className="text-center p-3 bg-white/5 rounded-lg">
                <div className="text-2xl font-bold text-[#ff6b35]">{accuracy}%</div>
                <div className="text-sm text-gray-600">Accuracy</div>
              </div>
            </div>
          </motion.div>

          {/* Question Panel */}
          <AnimatePresence>
            {showQuestion && currentQuestion && (
              <motion.div
                initial={{ opacity: 0, y: 20, scale: 0.9 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -20, scale: 0.9 }}
                className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg p-6 border-2 border-[#ff8c00] shadow-lg"
              >
                <div className="mb-4">
                  <span className="inline-block px-3 py-1 text-xs font-medium bg-[#ff8c00] text-white rounded-full mb-2">
                    {currentQuestion.category}
                  </span>
                  <h3 className="text-lg font-semibold text-gray-800 mb-4">
                    {currentQuestion.question}
                  </h3>
                </div>

                <div className="space-y-2 mb-4">
                  {currentQuestion.options.map((option, index) => {
                    const isSelected = selectedAnswer === index
                    const isCorrectOption = index === currentQuestion.correct
                    const baseClasses = "w-full text-left p-3 rounded-lg border-2 transition-all font-medium"

                    let stateClasses = ""
                    if (selectedAnswer === null) {
                      stateClasses = "border-gray-200 bg-white text-gray-900 hover:border-[#ff8c00] hover:bg-[#ff8c00]/10"
                    } else if (isSelected && isCorrectOption) {
                      stateClasses = "border-green-500 bg-green-50 text-green-800"
                    } else if (isSelected && !isCorrectOption) {
                      stateClasses = "border-red-500 bg-red-50 text-red-800"
                    } else if (!isSelected && isCorrectOption) {
                      stateClasses = "border-green-500 bg-green-50 text-green-800"
                    } else {
                      stateClasses = "border-gray-200 bg-gray-50 text-gray-600"
                    }

                    return (
                      <motion.button
                        key={index}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={() => handleAnswerSelect(index)}
                        disabled={selectedAnswer !== null}
                        className={`${baseClasses} ${stateClasses}`}
                      >
                        <span className="font-medium mr-2 text-sm">
                          {String.fromCharCode(65 + index)}.
                        </span>
                        <span className="text-sm md:text-base">{option}</span>
                      </motion.button>
                    )
                  })}
                </div>

                {showExplanation && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    className="border-t border-gray-200 pt-4"
                  >
                    <h4 className="font-semibold text-gray-800 mb-2">Explanation:</h4>
                    <p className="text-gray-600 mb-4">{currentQuestion.explanation}</p>
                    <motion.button
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                      onClick={continueGame}
                      className="w-full py-2 bg-[#ff8c00] text-white rounded-lg font-medium hover:bg-[#ff6b35] transition-colors"
                    >
                      Continue Game
                    </motion.button>
                  </motion.div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  )
}