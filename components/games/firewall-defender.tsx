"use client"

import { useState, useEffect, useRef, type MouseEvent } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { Shield, Network, Clock, Target, ArrowRight } from "lucide-react"

interface NetworkPacket {
  id: number
  sourceIP: string
  destPort: number
  protocol: 'TCP' | 'UDP' | 'ICMP'
  payload: string
  isMalicious: boolean
  threatType?: string
  timestamp: number
}

interface FirewallRule {
  id: number
  action: 'ALLOW' | 'BLOCK'
  sourceIP?: string
  destPort?: number
  protocol?: string
  description: string
}

export default function FirewallDefenderGame() {
  const [packets, setPackets] = useState<NetworkPacket[]>([])
  const [rules, setRules] = useState<FirewallRule[]>([
    { id: 1, action: 'ALLOW', destPort: 80, protocol: 'TCP', description: 'Allow web traffic' },
    { id: 2, action: 'ALLOW', destPort: 443, protocol: 'TCP', description: 'Allow HTTPS traffic' },
    { id: 3, action: 'BLOCK', sourceIP: '192.168.1.100', description: 'Block suspicious IP' }
  ])
  const [gameRunning, setGameRunning] = useState(false)
  const [timeLeft, setTimeLeft] = useState(90)
  const [score, setScore] = useState(0)
  const [threatsBlocked, setThreatsBlocked] = useState(0)
  const [legitimateAllowed, setLegitimateAllowed] = useState(0)
  const [falsePositives, setFalsePositives] = useState(0)
  const [falseNegatives, setFalseNegatives] = useState(0)
  const [selectedPacket, setSelectedPacket] = useState<NetworkPacket | null>(null)
  const [newRule, setNewRule] = useState({
    action: 'BLOCK' as 'ALLOW' | 'BLOCK',
    sourceIP: '',
    destPort: '',
    protocol: '',
    description: ''
  })
  
  const packetGeneratorRef = useRef<NodeJS.Timeout>()
  const gameTimerRef = useRef<NodeJS.Timeout>()

  const generatePacket = (): NetworkPacket => {
    const isMalicious = Math.random() < 0.3 // 30% chance of malicious packet
    
    if (isMalicious) {
      const threats = [
        {
          sourceIP: '10.0.0.' + Math.floor(Math.random() * 255),
          destPort: 80,
          protocol: 'TCP' as const,
          payload: 'SYN FLOOD ATTACK',
          threatType: 'SYN Flood Attack'
        },
        {
          sourceIP: '203.0.113.' + Math.floor(Math.random() * 255),
          destPort: Math.floor(Math.random() * 10000) + 8000,
          protocol: 'TCP' as const,
          payload: 'PORT SCAN PROBE',
          threatType: 'Port Scanning'
        },
        {
          sourceIP: '198.51.100.' + Math.floor(Math.random() * 255),
          destPort: 443,
          protocol: 'UDP' as const,
          payload: 'MALWARE PAYLOAD C2',
          threatType: 'Malware Communication'
        },
        {
          sourceIP: '10.0.0.' + Math.floor(Math.random() * 255),
          destPort: 80,
          protocol: 'UDP' as const,
          payload: 'DDOS FLOOD TRAFFIC',
          threatType: 'DDoS Attack'
        }
      ]
      
      const threat = threats[Math.floor(Math.random() * threats.length)]
      return {
        id: Date.now() + Math.random(),
        ...threat,
        isMalicious: true,
        timestamp: Date.now()
      }
    } else {
      const legitimate = [
        {
          sourceIP: '192.168.1.' + Math.floor(Math.random() * 50 + 10),
          destPort: 80,
          protocol: 'TCP' as const,
          payload: 'HTTP GET /index.html'
        },
        {
          sourceIP: '192.168.1.' + Math.floor(Math.random() * 50 + 10),
          destPort: 443,
          protocol: 'TCP' as const,
          payload: 'HTTPS POST /api/data'
        },
        {
          sourceIP: '172.16.0.' + Math.floor(Math.random() * 100),
          destPort: 22,
          protocol: 'TCP' as const,
          payload: 'SSH Connection'
        },
        {
          sourceIP: '192.168.1.' + Math.floor(Math.random() * 50 + 10),
          destPort: 53,
          protocol: 'UDP' as const,
          payload: 'DNS Query google.com'
        }
      ]
      
      const legit = legitimate[Math.floor(Math.random() * legitimate.length)]
      return {
        id: Date.now() + Math.random(),
        ...legit,
        isMalicious: false,
        timestamp: Date.now()
      }
    }
  }

  const checkFirewallRules = (packet: NetworkPacket): boolean => {
    // Check if packet should be blocked based on rules
    for (const rule of rules) {
      let matches = true
      
      if (rule.sourceIP && packet.sourceIP !== rule.sourceIP && !packet.sourceIP.startsWith(rule.sourceIP.split('.').slice(0, 3).join('.') + '.')) {
        matches = false
      }
      
      if (rule.destPort && packet.destPort !== rule.destPort) {
        matches = false
      }
      
      if (rule.protocol && packet.protocol !== rule.protocol) {
        matches = false
      }
      
      if (matches) {
        return rule.action === 'BLOCK'
      }
    }
    
    return false // Default allow
  }

  const processPacket = (packet: NetworkPacket) => {
    const shouldBlock = checkFirewallRules(packet)
    const actuallyMalicious = packet.isMalicious
    
    if (shouldBlock && actuallyMalicious) {
      // Correctly blocked threat
      setThreatsBlocked(prev => prev + 1)
      setScore(prev => prev + 10)
    } else if (!shouldBlock && !actuallyMalicious) {
      // Correctly allowed legitimate traffic
      setLegitimateAllowed(prev => prev + 1)
      setScore(prev => prev + 5)
    } else if (shouldBlock && !actuallyMalicious) {
      // False positive - blocked legitimate traffic
      setFalsePositives(prev => prev + 1)
      setScore(prev => prev - 3)
    } else if (!shouldBlock && actuallyMalicious) {
      // False negative - allowed malicious traffic
      setFalseNegatives(prev => prev + 1)
      setScore(prev => prev - 5)
    }
    
    // Remove packet after processing
    setTimeout(() => {
      setPackets(prev => prev.filter(p => p.id !== packet.id))
    }, 2000)
  }

  const startGame = () => {
    setGameRunning(true)
    setTimeLeft(90)
    setScore(0)
    setThreatsBlocked(0)
    setLegitimateAllowed(0)
    setFalsePositives(0)
    setFalseNegatives(0)
    setPackets([])

    // Start packet generation
    packetGeneratorRef.current = setInterval(() => {
      const newPacket = generatePacket()
      setPackets(prev => [...prev, newPacket])
      
      // Auto-process packet after 3 seconds if not manually handled
      setTimeout(() => {
        processPacket(newPacket)
      }, 3000)
    }, 1000)

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
    if (packetGeneratorRef.current) clearInterval(packetGeneratorRef.current)
    if (gameTimerRef.current) clearInterval(gameTimerRef.current)
  }

  const addRule = () => {
    if (newRule.description) {
      const rule: FirewallRule = {
        id: Date.now(),
        action: newRule.action,
        sourceIP: newRule.sourceIP || undefined,
        destPort: newRule.destPort ? parseInt(newRule.destPort) : undefined,
        protocol: newRule.protocol || undefined,
        description: newRule.description
      }
      
      setRules(prev => [...prev, rule])
      setNewRule({
        action: 'BLOCK',
        sourceIP: '',
        destPort: '',
        protocol: '',
        description: ''
      })
    }
  }

  const removeRule = (ruleId: number) => {
    setRules(prev => prev.filter(r => r.id !== ruleId))
  }

  const manuallyProcessPacket = (packet: NetworkPacket, action: 'allow' | 'block') => {
    const shouldBlock = action === 'block'
    const actuallyMalicious = packet.isMalicious
    
    if (shouldBlock && actuallyMalicious) {
      setThreatsBlocked(prev => prev + 1)
      setScore(prev => prev + 15) // Bonus for manual correct decision
    } else if (!shouldBlock && !actuallyMalicious) {
      setLegitimateAllowed(prev => prev + 1)
      setScore(prev => prev + 8)
    } else if (shouldBlock && !actuallyMalicious) {
      setFalsePositives(prev => prev + 1)
      setScore(prev => prev - 2)
    } else {
      setFalseNegatives(prev => prev + 1)
      setScore(prev => prev - 8)
    }
    
    setPackets(prev => prev.filter(p => p.id !== packet.id))
  }

  useEffect(() => {
    return () => {
      if (packetGeneratorRef.current) clearInterval(packetGeneratorRef.current)
      if (gameTimerRef.current) clearInterval(gameTimerRef.current)
    }
  }, [])

  const getPacketColor = (packet: NetworkPacket) => {
    if (packet.isMalicious) {
      return 'border-red-300 bg-red-50'
    }
    return 'border-green-300 bg-green-50'
  }

  const getThreatTypeColor = (threatType?: string) => {
    switch (threatType) {
      case 'SYN Flood Attack': return 'bg-red-100 text-red-800'
      case 'Port Scanning': return 'bg-orange-100 text-orange-800'
      case 'DDoS Attack': return 'bg-purple-100 text-purple-800'
      case 'Malware Communication': return 'bg-pink-100 text-pink-800'
      default: return 'bg-green-100 text-green-800'
    }
  }

  return (
    <div className="max-w-7xl mx-auto p-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center mb-6"
      >
        <h1 className="text-3xl font-bold text-[#ff8c00] mb-2 flex items-center justify-center gap-3">
          <Shield className="w-8 h-8" />
          🛡️ Firewall Defender
          <Network className="w-8 h-8" />
        </h1>
        <p className="text-gray-600">Configure firewall rules to block malicious traffic while allowing legitimate connections</p>
      </motion.div>

      <div className="grid lg:grid-cols-4 gap-6">
        {/* Game Stats */}
        <motion.div 
          initial={{ x: -20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg p-6 border-2 border-[#ff8c00]"
        >
          <h2 className="text-lg font-semibold text-[#ff8c00] mb-4 flex items-center gap-2">
            <Target className="w-5 h-5" />
            Defense Stats
          </h2>
          
          <div className="space-y-3">
            <div className="text-center p-3 bg-white/50 rounded-lg">
              <div className="text-2xl font-bold text-[#ff8c00]">{score}</div>
              <div className="text-sm text-gray-600">Score</div>
            </div>
            
            <div className="text-center p-3 bg-green-50 rounded-lg">
              <div className="text-xl font-bold text-green-600">{threatsBlocked}</div>
              <div className="text-xs text-gray-600">Threats Blocked</div>
            </div>
            
            <div className="text-center p-3 bg-blue-50 rounded-lg">
              <div className="text-xl font-bold text-blue-600">{legitimateAllowed}</div>
              <div className="text-xs text-gray-600">Legit Allowed</div>
            </div>
            
            <div className="text-center p-3 bg-orange-50 rounded-lg">
              <div className="text-xl font-bold text-orange-600">{falsePositives}</div>
              <div className="text-xs text-gray-600">False Positives</div>
            </div>
            
            <div className="text-center p-3 bg-red-50 rounded-lg">
              <div className="text-xl font-bold text-red-600">{falseNegatives}</div>
              <div className="text-xs text-gray-600">False Negatives</div>
            </div>
          </div>

          <div className="mt-4 text-center">
            {gameRunning && (
              <div className="p-3 bg-purple-50 rounded-lg">
                <div className="text-xl font-bold text-purple-600 flex items-center justify-center gap-2">
                  <Clock className="w-5 h-5" />
                  {timeLeft}s
                </div>
                <div className="text-xs text-gray-600">Time Left</div>
              </div>
            )}
          </div>

          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={gameRunning ? endGame : startGame}
            className={`w-full mt-4 py-2 rounded-lg font-medium transition-colors ${
              gameRunning 
                ? 'bg-red-500 hover:bg-red-600 text-white' 
                : 'bg-[#ff8c00] hover:bg-[#ff6b35] text-white'
            }`}
          >
            {gameRunning ? 'Stop Defense' : 'Start Defense'}
          </motion.button>
        </motion.div>

        {/* Network Traffic */}
        <motion.div 
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          className="lg:col-span-2 bg-gradient-to-br from-gray-50 to-slate-50 rounded-lg p-6 border-2 border-gray-300"
        >
          <h2 className="text-xl font-semibold text-gray-700 mb-4 flex items-center gap-2">
            <Network className="w-5 h-5" />
            Network Traffic Monitor
          </h2>

          <div className="space-y-3 max-h-96 overflow-y-auto">
            <AnimatePresence>
              {packets.map((packet) => (
                <motion.div
                  key={packet.id}
                  initial={{ opacity: 0, x: 50 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -50 }}
                  className={`p-4 rounded-lg border-2 ${getPacketColor(packet)} cursor-pointer hover:shadow-md transition-all`}
                  onClick={() => setSelectedPacket(packet)}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm bg-white px-2 py-1 rounded">
                        {packet.sourceIP}
                      </span>
                      <ArrowRight className="w-4 h-4 text-gray-400" />
                      <span className="font-mono text-sm bg-white px-2 py-1 rounded">
                        :{packet.destPort}
                      </span>
                      <span className="px-2 py-1 text-xs bg-gray-100 rounded">
                        {packet.protocol}
                      </span>
                    </div>
                    {packet.threatType && (
                      <span className={`px-2 py-1 text-xs rounded ${getThreatTypeColor(packet.threatType)}`}>
                        {packet.threatType}
                      </span>
                    )}
                  </div>
                  
                  <p className="text-sm text-gray-700 font-mono truncate">
                    {packet.payload}
                  </p>
                  
                  {gameRunning && (
                    <div className="mt-2 flex gap-2">
                      <motion.button
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        onClick={(event: MouseEvent<HTMLButtonElement>) => {
                          event.stopPropagation()
                          manuallyProcessPacket(packet, 'allow')
                        }}
                        className="px-3 py-1 text-xs bg-green-500 hover:bg-green-600 text-white rounded"
                      >
                        Allow
                      </motion.button>
                      <motion.button
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        onClick={(event: MouseEvent<HTMLButtonElement>) => {
                          event.stopPropagation()
                          manuallyProcessPacket(packet, 'block')
                        }}
                        className="px-3 py-1 text-xs bg-red-500 hover:bg-red-600 text-white rounded"
                      >
                        Block
                      </motion.button>
                    </div>
                  )}
                </motion.div>
              ))}
            </AnimatePresence>
            
            {packets.length === 0 && (
              <div className="text-center py-8 text-gray-500">
                <Network className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>{gameRunning ? 'Monitoring network traffic...' : 'Start the game to see network packets'}</p>
              </div>
            )}
          </div>
        </motion.div>

        {/* Firewall Rules */}
        <motion.div 
          initial={{ x: 20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          className="bg-gradient-to-br from-orange-50 to-red-50 rounded-lg p-6 border-2 border-orange-300"
        >
          <h2 className="text-lg font-semibold text-orange-700 mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5" />
            Firewall Rules
          </h2>
          
          {/* Add Rule Form */}
          <div className="space-y-2 mb-4 p-3 bg-white/50 rounded-lg">
            <select
              value={newRule.action}
              onChange={(e) => setNewRule(prev => ({ ...prev, action: e.target.value as 'ALLOW' | 'BLOCK' }))}
              className="w-full px-2 py-1 text-sm border rounded"
            >
              <option value="BLOCK">BLOCK</option>
              <option value="ALLOW">ALLOW</option>
            </select>
            
            <input
              type="text"
              placeholder="Source IP (optional)"
              value={newRule.sourceIP}
              onChange={(e) => setNewRule(prev => ({ ...prev, sourceIP: e.target.value }))}
              className="w-full px-2 py-1 text-sm border rounded"
            />
            
            <input
              type="number"
              placeholder="Port (optional)"
              value={newRule.destPort}
              onChange={(e) => setNewRule(prev => ({ ...prev, destPort: e.target.value }))}
              className="w-full px-2 py-1 text-sm border rounded"
            />
            
            <select
              value={newRule.protocol}
              onChange={(e) => setNewRule(prev => ({ ...prev, protocol: e.target.value }))}
              className="w-full px-2 py-1 text-sm border rounded"
            >
              <option value="">Any Protocol</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
            
            <input
              type="text"
              placeholder="Description"
              value={newRule.description}
              onChange={(e) => setNewRule(prev => ({ ...prev, description: e.target.value }))}
              className="w-full px-2 py-1 text-sm border rounded"
            />
            
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={addRule}
              className="w-full py-1 bg-[#ff8c00] text-white rounded text-sm hover:bg-[#ff6b35] transition-colors"
            >
              Add Rule
            </motion.button>
          </div>

          {/* Rules List */}
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {rules.map((rule) => (
              <motion.div
                key={rule.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className={`p-2 rounded border text-xs ${
                  rule.action === 'BLOCK' 
                    ? 'bg-red-100 border-red-300' 
                    : 'bg-green-100 border-green-300'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className={`font-medium ${
                    rule.action === 'BLOCK' ? 'text-red-700' : 'text-green-700'
                  }`}>
                    {rule.action}
                  </span>
                  <button
                    onClick={() => removeRule(rule.id)}
                    className="text-gray-500 hover:text-red-500"
                  >
                    ×
                  </button>
                </div>
                <p className="text-gray-700">{rule.description}</p>
                <div className="text-gray-600 mt-1">
                  {rule.sourceIP && <span>IP: {rule.sourceIP} </span>}
                  {rule.destPort && <span>Port: {rule.destPort} </span>}
                  {rule.protocol && <span>Proto: {rule.protocol}</span>}
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Packet Detail Modal */}
      <AnimatePresence>
        {selectedPacket && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
            onClick={() => setSelectedPacket(null)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white rounded-lg p-6 max-w-md w-full mx-4"
              onClick={(event: MouseEvent<HTMLDivElement>) => event.stopPropagation()}
            >
              <h3 className="text-lg font-semibold mb-4">Packet Details</h3>
              <div className="space-y-2 text-sm">
                <div><strong>Source IP:</strong> {selectedPacket.sourceIP}</div>
                <div><strong>Destination Port:</strong> {selectedPacket.destPort}</div>
                <div><strong>Protocol:</strong> {selectedPacket.protocol}</div>
                <div><strong>Payload:</strong> <code className="bg-gray-100 p-1 rounded">{selectedPacket.payload}</code></div>
                <div><strong>Timestamp:</strong> {new Date(selectedPacket.timestamp).toLocaleTimeString()}</div>
                {selectedPacket.threatType && (
                  <div><strong>Threat Type:</strong> <span className={`px-2 py-1 rounded ${getThreatTypeColor(selectedPacket.threatType)}`}>{selectedPacket.threatType}</span></div>
                )}
                <div><strong>Status:</strong> <span className={selectedPacket.isMalicious ? 'text-red-600' : 'text-green-600'}>{selectedPacket.isMalicious ? 'Malicious' : 'Legitimate'}</span></div>
              </div>
              <button
                onClick={() => setSelectedPacket(null)}
                className="mt-4 w-full py-2 bg-gray-500 text-white rounded hover:bg-gray-600 transition-colors"
              >
                Close
              </button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

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
                <p>Final Score: <span className="font-bold text-[#ff8c00]">{score}</span></p>
                <p>Threats Blocked: <span className="font-bold text-green-600">{threatsBlocked}</span></p>
                <p>Legitimate Allowed: <span className="font-bold text-blue-600">{legitimateAllowed}</span></p>
                <p>False Positives: <span className="font-bold text-orange-600">{falsePositives}</span></p>
                <p>False Negatives: <span className="font-bold text-red-600">{falseNegatives}</span></p>
                <p className="mt-4">
                  Efficiency: <span className="font-bold text-purple-600">
                    {threatsBlocked + legitimateAllowed > 0 
                      ? Math.round(((threatsBlocked + legitimateAllowed) / (threatsBlocked + legitimateAllowed + falsePositives + falseNegatives)) * 100)
                      : 0}%
                  </span>
                </p>
              </div>
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={startGame}
                className="w-full mt-6 py-2 bg-[#ff8c00] text-white rounded-lg font-medium hover:bg-[#ff6b35] transition-colors"
              >
                Defend Again
              </motion.button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}