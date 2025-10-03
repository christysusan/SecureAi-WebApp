"use client"

import { useState, useEffect } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { Key, Lock, Unlock, Eye, EyeOff, Lightbulb, CheckCircle, RotateCcw, Brain } from "lucide-react"

interface CryptoPuzzle {
  id: number
  type: 'caesar' | 'substitution' | 'vigenere' | 'base64' | 'morse'
  plaintext: string
  ciphertext: string
  key?: string | number
  hint: string
  difficulty: 'easy' | 'medium' | 'hard'
  category: string
}

type AlgorithmOption = 'auto' | 'caesar' | 'base64' | 'morse' | 'vigenere'

const cryptoPuzzles: CryptoPuzzle[] = [
  {
    id: 1,
    type: 'caesar',
    plaintext: 'ATTACK AT DAWN',
    ciphertext: 'DWWDFN DW GDZQ',
    key: 3,
    hint: 'Julius Caesar used this cipher. Try shifting letters by small numbers.',
    difficulty: 'easy',
    category: 'Classical Cipher'
  },
  {
    id: 2,
    type: 'caesar',
    plaintext: 'SECURITY IS IMPORTANT',
    ciphertext: 'ZLXBYPAF PZ PTWVYHAU',
    key: 7,
    hint: 'Each letter is shifted by the same amount. Lucky number 7?',
    difficulty: 'easy',
    category: 'Classical Cipher'
  },
  {
    id: 3,
    type: 'base64',
    plaintext: 'PASSWORD123',
    ciphertext: 'UEFTU1dPUkQxMjM=',
    hint: 'This encoding uses A-Z, a-z, 0-9, +, / and = for padding.',
    difficulty: 'medium',
    category: 'Encoding'
  },
  {
    id: 4,
    type: 'morse',
    plaintext: 'SOS',
    ciphertext: '... --- ...',
    hint: 'Dit dah dit, dah dah dah, dit dah dit. International distress signal.',
    difficulty: 'medium',
    category: 'Telegraph Code'
  },
  {
    id: 5,
    type: 'vigenere',
    plaintext: 'CRYPTO',
    ciphertext: 'DTPTQV',
    key: 'KEY',
    hint: 'This cipher uses a keyword. The key repeats: K-E-Y-K-E-Y...',
    difficulty: 'hard',
    category: 'Polyalphabetic'
  }
]

const morseCode: { [key: string]: string } = {
  'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
  'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
  'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
  'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
  'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
  '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
  '8': '---..', '9': '----.', ' ': '/'
}

export default function EncryptionPuzzleGame() {
  const [currentPuzzle, setCurrentPuzzle] = useState<CryptoPuzzle | null>(null)
  const [puzzleIndex, setPuzzleIndex] = useState(0)
  const [userInput, setUserInput] = useState('')
  const [showHint, setShowHint] = useState(false)
  const [showKey, setShowKey] = useState(false)
  const [attempts, setAttempts] = useState(0)
  const [solved, setSolved] = useState(false)
  const [score, setScore] = useState(0)
  const [puzzlesSolved, setPuzzlesSolved] = useState(0)
  const [gameStarted, setGameStarted] = useState(false)
  const [selectedAlgorithm, setSelectedAlgorithm] = useState<AlgorithmOption>('auto')
  const [caesarShift, setCaesarShift] = useState(1)
  const [lastMethod, setLastMethod] = useState('')

  useEffect(() => {
    if (gameStarted && cryptoPuzzles[puzzleIndex]) {
      setCurrentPuzzle(cryptoPuzzles[puzzleIndex])
      setUserInput('')
      setShowHint(false)
      setShowKey(false)
      setAttempts(0)
  setSolved(false)
  setLastMethod('')
    }
  }, [puzzleIndex, gameStarted])

  const startGame = () => {
    setGameStarted(true)
    setPuzzleIndex(0)
    setScore(0)
    setPuzzlesSolved(0)
    setLastMethod('')
  }

  const caesarCipher = (text: string, shift: number, decode: boolean = false): string => {
    const s = decode ? (26 - shift) % 26 : shift
    return text.toUpperCase().replace(/[A-Z]/g, (char) => {
      const code = char.charCodeAt(0) - 65
      const shifted = (code + s) % 26
      return String.fromCharCode(shifted + 65)
    })
  }

  const base64Decode = (encoded: string): string => {
    try {
      return atob(encoded)
    } catch {
      return ''
    }
  }

  const morseToText = (morse: string): string => {
    const reverseMorse = Object.fromEntries(
      Object.entries(morseCode).map(([letter, code]) => [code, letter])
    )
    return morse.split(' ').map(code => reverseMorse[code] || '').join('')
  }

  const vigenereDecode = (ciphertext: string, key: string): string => {
    const keyRepeated = key.repeat(Math.ceil(ciphertext.length / key.length)).substring(0, ciphertext.length)
    return ciphertext.split('').map((char, i) => {
      if (char.match(/[A-Z]/)) {
        const charCode = char.charCodeAt(0) - 65
        const keyCode = keyRepeated[i].charCodeAt(0) - 65
        const decoded = (charCode - keyCode + 26) % 26
        return String.fromCharCode(decoded + 65)
      }
      return char
    }).join('')
  }

  const autoDecrypt = (ciphertext: string): { result: string, method: string } => {
    // Try Caesar cipher with different shifts
    for (let shift = 1; shift <= 25; shift++) {
      const result = caesarCipher(ciphertext, shift, true)
      if (currentPuzzle && result === currentPuzzle.plaintext) {
        return { result, method: `Caesar Cipher (shift ${shift})` }
      }
    }

    // Try Base64
    try {
      const result = base64Decode(ciphertext)
      if (currentPuzzle && result === currentPuzzle.plaintext) {
        return { result, method: 'Base64 Decoding' }
      }
    } catch {}

    // Try Vigenère if key is known
    if (currentPuzzle?.key && typeof currentPuzzle.key === 'string') {
      const result = vigenereDecode(ciphertext, currentPuzzle.key.toUpperCase())
      if (currentPuzzle.plaintext === result) {
        return { result, method: `Vigenère Cipher (key ${currentPuzzle.key.toUpperCase()})` }
      }
    }

    // Try Morse Code
    try {
      const result = morseToText(ciphertext)
      if (currentPuzzle && result === currentPuzzle.plaintext) {
        return { result, method: 'Morse Code' }
      }
    } catch {}

    return { result: '', method: 'Unknown' }
  }

  const attemptDecryption = () => {
    if (!currentPuzzle) return

    let decrypted = ''
    let method = ''

    if (selectedAlgorithm === 'auto') {
      const result = autoDecrypt(currentPuzzle.ciphertext)
      decrypted = result.result
      method = result.method
    } else if (selectedAlgorithm === 'caesar') {
      decrypted = caesarCipher(currentPuzzle.ciphertext, caesarShift, true)
      method = `Caesar Cipher (shift ${caesarShift})`
    } else if (selectedAlgorithm === 'base64') {
      decrypted = base64Decode(currentPuzzle.ciphertext)
      method = 'Base64 Decoding'
    } else if (selectedAlgorithm === 'morse') {
      decrypted = morseToText(currentPuzzle.ciphertext)
      method = 'Morse Code'
    } else if (selectedAlgorithm === 'vigenere') {
      if (typeof currentPuzzle.key === 'string' && currentPuzzle.key.length > 0) {
        decrypted = vigenereDecode(currentPuzzle.ciphertext, currentPuzzle.key.toUpperCase())
        method = `Vigenère Cipher (key ${currentPuzzle.key.toUpperCase()})`
      } else {
        method = 'Vigenère Cipher (key required)'
      }
    }

    setUserInput(decrypted)
    setAttempts(prev => prev + 1)
    if (method) {
      setLastMethod(method)
    }

    if (decrypted === currentPuzzle.plaintext) {
      setSolved(true)
      setPuzzlesSolved(prev => prev + 1)
      
      // Calculate score based on difficulty and attempts
      let points = 0
      switch (currentPuzzle.difficulty) {
        case 'easy': points = 10; break
        case 'medium': points = 20; break
        case 'hard': points = 30; break
      }
      
      // Bonus for fewer attempts
      const attemptBonus = Math.max(0, 5 - attempts)
      const hintPenalty = showHint ? 2 : 0
      const keyPenalty = showKey ? 3 : 0
      
      const totalPoints = Math.max(1, points + attemptBonus - hintPenalty - keyPenalty)
      setScore(prev => prev + totalPoints)
    }
  }

  const nextPuzzle = () => {
    if (puzzleIndex < cryptoPuzzles.length - 1) {
      setPuzzleIndex(prev => prev + 1)
    } else {
      // Game complete
      setGameStarted(false)
    }
    setLastMethod('')
  }

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy': return 'bg-green-100 text-green-800'
      case 'medium': return 'bg-yellow-100 text-yellow-800'
      case 'hard': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  if (!gameStarted) {
    return (
      <div className="max-w-4xl mx-auto p-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center"
        >
          <h1 className="text-3xl font-bold text-[#ff8c00] mb-4 flex items-center justify-center gap-3">
            <Key className="w-8 h-8" />
            🔑 Crypto Puzzle Master
            <Lock className="w-8 h-8" />
          </h1>
          <p className="text-gray-600 mb-8">Solve encryption puzzles and master the art of cryptography!</p>
          
          <div className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg p-8 border-2 border-[#ff8c00] max-w-2xl mx-auto">
            <h2 className="text-xl font-semibold mb-4">How to Play</h2>
            <div className="text-left space-y-3 text-gray-700">
              <div className="flex items-start gap-3">
                <Brain className="w-5 h-5 text-[#ff8c00] mt-0.5" />
                <p>Analyze encrypted messages and find the decryption method</p>
              </div>
              <div className="flex items-start gap-3">
                <Key className="w-5 h-5 text-[#ff8c00] mt-0.5" />
                <p>Use different algorithms: Caesar cipher, Base64, Morse code, and more</p>
              </div>
              <div className="flex items-start gap-3">
                <Lightbulb className="w-5 h-5 text-[#ff8c00] mt-0.5" />
                <p>Get hints if you&rsquo;re stuck, but they&rsquo;ll reduce your score</p>
              </div>
            </div>
            
            <div className="mt-6 text-sm text-gray-600 bg-white/50 p-4 rounded">
              <h3 className="font-semibold mb-2">Puzzle Types:</h3>
              <ul className="space-y-1">
                <li>• Caesar Cipher: Letter shifting</li>
                <li>• Base64: Binary-to-text encoding</li>
                <li>• Morse Code: Telegraph communication</li>
                <li>• Vigenère: Keyword-based encryption</li>
                <li>• Substitution: Letter replacement</li>
              </ul>
            </div>
            
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={startGame}
              className="mt-6 px-8 py-3 bg-[#ff8c00] text-white rounded-lg font-medium hover:bg-[#ff6b35] transition-colors"
            >
              Start Puzzle Challenge
            </motion.button>
          </div>
        </motion.div>
      </div>
    )
  }

  if (!currentPuzzle) return null

  return (
    <div className="max-w-6xl mx-auto p-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center mb-6"
      >
        <h1 className="text-3xl font-bold text-[#ff8c00] mb-2 flex items-center justify-center gap-3">
          <Key className="w-8 h-8" />
          🔑 Crypto Puzzle Master
          <Lock className="w-8 h-8" />
        </h1>
        <p className="text-gray-600">Puzzle {puzzleIndex + 1} of {cryptoPuzzles.length}</p>
      </motion.div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Puzzle Info */}
        <motion.div 
          initial={{ x: -20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg p-6 border-2 border-[#ff8c00]"
        >
          <h2 className="text-lg font-semibold text-[#ff8c00] mb-4 flex items-center gap-2">
            <Brain className="w-5 h-5" />
            Puzzle Info
          </h2>
          
          <div className="space-y-4">
            <div className="text-center p-3 bg-white/50 rounded-lg">
              <div className="text-2xl font-bold text-[#ff8c00]">{score}</div>
              <div className="text-sm text-gray-600">Total Score</div>
            </div>
            
            <div className="text-center p-3 bg-green-50 rounded-lg">
              <div className="text-xl font-bold text-green-600">{puzzlesSolved}</div>
              <div className="text-xs text-gray-600">Puzzles Solved</div>
            </div>
            
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">Category:</span>
                <span className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded">
                  {currentPuzzle.category}
                </span>
              </div>
              
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">Difficulty:</span>
                <span className={`px-2 py-1 text-xs rounded ${getDifficultyColor(currentPuzzle.difficulty)}`}>
                  {currentPuzzle.difficulty.toUpperCase()}
                </span>
              </div>
              
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">Attempts:</span>
                <span className="font-bold text-gray-700">{attempts}</span>
              </div>
            </div>

            <div className="space-y-2">
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setShowHint(!showHint)}
                className="w-full flex items-center justify-center gap-2 py-2 bg-yellow-100 hover:bg-yellow-200 text-yellow-800 rounded-lg transition-colors"
              >
                <Lightbulb className="w-4 h-4" />
                {showHint ? 'Hide Hint' : 'Show Hint'} (-2 pts)
              </motion.button>
              
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setShowKey(!showKey)}
                className="w-full flex items-center justify-center gap-2 py-2 bg-red-100 hover:bg-red-200 text-red-800 rounded-lg transition-colors"
              >
                {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                {showKey ? 'Hide Key' : 'Show Key'} (-3 pts)
              </motion.button>
            </div>

            <AnimatePresence>
              {showHint && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg"
                >
                  <p className="text-sm text-yellow-800">{currentPuzzle.hint}</p>
                </motion.div>
              )}
            </AnimatePresence>

            <AnimatePresence>
              {showKey && currentPuzzle.key && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="p-3 bg-red-50 border border-red-200 rounded-lg"
                >
                  <p className="text-sm text-red-800">
                    <strong>Key:</strong> {currentPuzzle.key}
                  </p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </motion.div>

        {/* Puzzle Interface */}
        <motion.div 
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          className="bg-white rounded-lg p-6 border-2 border-gray-200 shadow-lg"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            {solved ? <Unlock className="w-5 h-5 text-green-500" /> : <Lock className="w-5 h-5 text-red-500" />}
            Encrypted Message
          </h2>

          <div className="space-y-4">
            <div className="p-4 bg-gray-100 rounded-lg">
              <h3 className="text-sm font-medium text-gray-700 mb-2">Ciphertext:</h3>
              <code className="font-mono text-lg break-all bg-white p-3 rounded border block">
                {currentPuzzle.ciphertext}
              </code>
            </div>

            <div className="p-4 bg-green-50 rounded-lg">
              <h3 className="text-sm font-medium text-gray-700 mb-2">Your Decryption:</h3>
              <input
                type="text"
                value={userInput}
                onChange={(e) => setUserInput(e.target.value.toUpperCase())}
                placeholder="Enter the decrypted message..."
                className="w-full p-3 border border-gray-300 rounded-lg font-mono text-lg focus:ring-2 focus:ring-[#ff8c00] focus:border-[#ff8c00]"
                disabled={solved}
              />
            </div>

            {solved && (
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="p-4 bg-green-100 border border-green-300 rounded-lg"
              >
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="w-5 h-5 text-green-600" />
                  <span className="font-medium text-green-800">Puzzle Solved!</span>
                </div>
                <p className="text-sm text-green-700">
                  Correct! The message was: <strong>&quot;{currentPuzzle.plaintext}&quot;</strong>
                </p>
                <p className="text-xs text-green-600 mt-1">
                  Solved in {attempts} attempts {lastMethod ? `via ${lastMethod}` : `using ${currentPuzzle.type} cipher`}
                </p>
              </motion.div>
            )}

            <div className="flex items-center gap-2">
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setUserInput(currentPuzzle.plaintext)}
                className="px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600 transition-colors text-sm"
                disabled={solved}
              >
                Show Answer
              </motion.button>
              
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setUserInput('')}
                className="px-4 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400 transition-colors text-sm"
                disabled={solved}
              >
                <RotateCcw className="w-4 h-4 inline mr-1" />
                Clear
              </motion.button>
            </div>

            {solved && (
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={nextPuzzle}
                className="w-full py-3 bg-[#ff8c00] text-white rounded-lg font-medium hover:bg-[#ff6b35] transition-colors"
              >
                {puzzleIndex < cryptoPuzzles.length - 1 ? 'Next Puzzle' : 'Complete Challenge'}
              </motion.button>
            )}
          </div>
        </motion.div>

        {/* Decryption Tools */}
        <motion.div 
          initial={{ x: 20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          className="bg-gradient-to-br from-orange-50 to-red-50 rounded-lg p-6 border-2 border-orange-300"
        >
          <h2 className="text-lg font-semibold text-orange-700 mb-4 flex items-center gap-2">
            <Key className="w-5 h-5" />
            Decryption Tools
          </h2>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Algorithm:
              </label>
              <select
                value={selectedAlgorithm}
                onChange={(e) => setSelectedAlgorithm(e.target.value as AlgorithmOption)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#ff8c00] focus:border-[#ff8c00]"
                disabled={solved}
              >
                <option value="auto">Auto-detect</option>
                <option value="caesar">Caesar Cipher</option>
                <option value="base64">Base64 Decode</option>
                <option value="morse">Morse Code</option>
                <option value="vigenere">Vigenère Cipher</option>
              </select>
            </div>

            {selectedAlgorithm === 'caesar' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Caesar Shift: {caesarShift}
                </label>
                <input
                  type="range"
                  min="1"
                  max="25"
                  value={caesarShift}
                  onChange={(e) => setCaesarShift(parseInt(e.target.value))}
                  className="w-full"
                  disabled={solved}
                />
                <div className="flex justify-between text-xs text-gray-500 mt-1">
                  <span>1</span>
                  <span>25</span>
                </div>
              </div>
            )}

            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={attemptDecryption}
              disabled={solved}
              className="w-full py-3 bg-[#ff8c00] text-white rounded-lg font-medium hover:bg-[#ff6b35] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              🔓 Attempt Decryption
            </motion.button>

            <div className="border-t pt-4">
              <h3 className="text-sm font-semibold text-gray-700 mb-2">Quick Reference:</h3>
              <div className="text-xs text-gray-600 space-y-1">
                <div><strong>Caesar:</strong> A→D (shift 3)</div>
                <div><strong>Base64:</strong> Ends with =</div>
                <div><strong>Morse:</strong> Dots and dashes</div>
                <div><strong>Vigenère:</strong> Needs keyword</div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Game Complete Modal */}
      <AnimatePresence>
        {!gameStarted && puzzlesSolved > 0 && (
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
              <h2 className="text-2xl font-bold text-center mb-4">Cryptography Master!</h2>
              <div className="text-center space-y-2">
                <p>Final Score: <span className="font-bold text-[#ff8c00]">{score}</span></p>
                <p>Puzzles Solved: <span className="font-bold text-green-600">{puzzlesSolved}</span></p>
                <p>Success Rate: <span className="font-bold text-blue-600">
                  {Math.round((puzzlesSolved / cryptoPuzzles.length) * 100)}%
                </span></p>
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