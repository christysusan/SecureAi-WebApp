"use client"

import { useState, useEffect } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { 
  Terminal, 
  Flag, 
  Search, 
  CheckCircle,
  Clock,
  Trophy
} from "lucide-react"

interface FileSystemNode {
  name: string
  type: 'file' | 'directory'
  content?: string
  hidden?: boolean
  permissions?: string
  children?: FileSystemNode[]
  hasFlag?: boolean
  flagContent?: string
}

interface Command {
  command: string
  output: string
  timestamp: number
}

const fileSystem: FileSystemNode = {
  name: 'root',
  type: 'directory',
  permissions: 'drwxr-xr-x',
  children: [
    {
      name: 'home',
      type: 'directory',
      permissions: 'drwxr-xr-x',
      children: [
        {
          name: 'user',
          type: 'directory',
          permissions: 'drwxr-xr-x',
          children: [
            {
              name: 'documents',
              type: 'directory',
              permissions: 'drwxr-xr-x',
              children: [
                {
                  name: 'readme.txt',
                  type: 'file',
                  permissions: '-rw-r--r--',
                  content: 'Welcome to the CTF challenge!\nFind all hidden flags in the system.\nHint: Some files might be hidden...'
                },
                {
                  name: '.secret',
                  type: 'file',
                  permissions: '-rw-------',
                  hidden: true,
                  content: 'Flag 1: CTF{h1dd3n_f1l3s_4r3_3v3rywh3r3}'
                }
              ]
            },
            {
              name: '.bash_history',
              type: 'file',
              permissions: '-rw-------',
              hidden: true,
              content: 'ls -la\ncd /var/log\ncat system.log\nsudo rm suspicious_file.txt\necho "Flag 2: CTF{h1st0ry_t3lls_4ll}" > /tmp/.flag2'
            }
          ]
        }
      ]
    },
    {
      name: 'var',
      type: 'directory',
      permissions: 'drwxr-xr-x',
      children: [
        {
          name: 'log',
          type: 'directory',
          permissions: 'drwxr-xr-x',
          children: [
            {
              name: 'system.log',
              type: 'file',
              permissions: '-rw-r--r--',
              content: '[2024-10-03 10:15:23] User login: admin\n[2024-10-03 10:16:45] Failed login attempt from 192.168.1.100\n[2024-10-03 10:17:12] Suspicious file access: /etc/passwd\n[2024-10-03 10:18:33] Flag 3: CTF{l0g_f1l3s_r3v34l_s3cr3ts}\n[2024-10-03 10:19:44] System backup completed'
            },
            {
              name: 'access.log',
              type: 'file',
              permissions: '-rw-r--r--',
              content: '192.168.1.50 - - [03/Oct/2024:10:15:23 +0000] "GET /admin.php HTTP/1.1" 200 1234\n192.168.1.100 - - [03/Oct/2024:10:16:45 +0000] "POST /login.php HTTP/1.1" 401 567\n127.0.0.1 - - [03/Oct/2024:10:17:12 +0000] "GET /flag.txt HTTP/1.1" 404 404'
            }
          ]
        },
        {
          name: 'www',
          type: 'directory',
          permissions: 'drwxr-xr-x',
          children: [
            {
              name: 'html',
              type: 'directory',
              permissions: 'drwxr-xr-x',
              children: [
                {
                  name: 'index.html',
                  type: 'file',
                  permissions: '-rw-r--r--',
                  content: '<!DOCTYPE html>\n<html>\n<head><title>Welcome</title></head>\n<body>\n<h1>Welcome to our site!</h1>\n<!-- Flag 4: CTF{c0mm3nts_1n_s0urc3_c0d3} -->\n</body>\n</html>'
                },
                {
                  name: 'admin.php',
                  type: 'file',
                  permissions: '-rw-r--r--',
                  content: '<?php\n// Admin panel\nif ($_GET["debug"] == "true") {\n    echo "Flag 5: CTF{d3bug_p4r4m3t3rs_4r3_d4ng3r0us}";\n}\n?>'
                }
              ]
            }
          ]
        }
      ]
    },
    {
      name: 'tmp',
      type: 'directory',
      permissions: 'drwxrwxrwx',
      children: [
        {
          name: '.flag2',
          type: 'file',
          permissions: '-rw-------',
          hidden: true,
          content: 'Flag 2: CTF{h1st0ry_t3lls_4ll}'
        }
      ]
    },
    {
      name: 'etc',
      type: 'directory',
      permissions: 'drwxr-xr-x',
      children: [
        {
          name: 'passwd',
          type: 'file',
          permissions: '-rw-r--r--',
          content: 'root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:Regular User:/home/user:/bin/bash\nflag_user:x:1001:1001:Flag User CTF{us3r_4cc0unts_h1d3_1nf0}:/home/flag_user:/bin/bash'
        },
        {
          name: 'hosts',
          type: 'file',
          permissions: '-rw-r--r--',
          content: '127.0.0.1 localhost\n192.168.1.10 internal.company.com\n# Secret server: flag7.hidden.local CTF{dns_3ntr13s_c4n_h1d3_flags}'
        }
      ]
    }
  ]
}

const FLAGS = [
  'CTF{h1dd3n_f1l3s_4r3_3v3rywh3r3}',
  'CTF{h1st0ry_t3lls_4ll}',
  'CTF{l0g_f1l3s_r3v34l_s3cr3ts}',
  'CTF{c0mm3nts_1n_s0urc3_c0d3}',
  'CTF{d3bug_p4r4m3t3rs_4r3_d4ng3r0us}',
  'CTF{us3r_4cc0unts_h1d3_1nf0}',
  'CTF{dns_3ntr13s_c4n_h1d3_flags}'
]

export default function CTFMiniGame() {
  const [currentPath, setCurrentPath] = useState('/')
  const [commandHistory, setCommandHistory] = useState<Command[]>([])
  const [currentCommand, setCurrentCommand] = useState('')
  const [foundFlags, setFoundFlags] = useState<string[]>([])
  const [gameStarted, setGameStarted] = useState(false)
  const [timeLeft, setTimeLeft] = useState(300) // 5 minutes
  const [score, setScore] = useState(0)
  const [showHints, setShowHints] = useState(false)

  useEffect(() => {
    let timer: NodeJS.Timeout
    if (gameStarted && timeLeft > 0) {
      timer = setTimeout(() => setTimeLeft(prev => prev - 1), 1000)
    } else if (timeLeft === 0) {
      setGameStarted(false)
    }
    return () => clearTimeout(timer)
  }, [gameStarted, timeLeft])

  const findNode = (path: string): FileSystemNode | null => {
    const parts = path.split('/').filter(p => p)
    let current = fileSystem
    
    for (const part of parts) {
      if (current.children) {
        const child = current.children.find(c => c.name === part)
        if (child) {
          current = child
        } else {
          return null
        }
      } else {
        return null
      }
    }
    return current
  }

  const addCommand = (command: string, output: string) => {
    const newCommand: Command = {
      command,
      output,
      timestamp: Date.now()
    }
    setCommandHistory(prev => [...prev, newCommand])
  }

  const checkForFlags = (content: string) => {
    FLAGS.forEach(flag => {
      if (content.includes(flag) && !foundFlags.includes(flag)) {
        setFoundFlags(prev => [...prev, flag])
        setScore(prev => prev + 100)
        addCommand('', `🎉 FLAG FOUND: ${flag}`)
      }
    })
  }

  const executeCommand = (cmd: string) => {
    const parts = cmd.trim().split(' ')
    const command = parts[0]
    const args = parts.slice(1)

    switch (command) {
      case 'ls': {
        const showHidden = args.includes('-a') || args.includes('-la')
        const longFormat = args.includes('-l') || args.includes('-la')
        const targetPath = args.find(arg => !arg.startsWith('-')) || currentPath
        const node = findNode(targetPath)
        
        if (!node || node.type !== 'directory') {
          addCommand(cmd, `ls: ${targetPath}: No such file or directory`)
          return
        }

        let output = ''
        if (node.children) {
          const visibleChildren = showHidden 
            ? node.children 
            : node.children.filter(child => !child.hidden)
          
          if (longFormat) {
            output = visibleChildren.map(child => {
              const typeIndicator = child.type === 'directory' ? 'd' : '-'
              const perms = child.permissions || 'rwxr-xr-x'
              const size = child.content ? child.content.length : 4096
              return `${typeIndicator}${perms} 1 user user ${size.toString().padStart(8)} Oct  3 10:15 ${child.name}`
            }).join('\n')
          } else {
            output = visibleChildren.map(child => child.name).join('  ')
          }
        }
        addCommand(cmd, output)
        break
      }

      case 'cd': {
        const targetPath = args[0] || '/home/user'
        const newPath = targetPath.startsWith('/') ? targetPath : `${currentPath}/${targetPath}`
        const normalizedPath = newPath.replace(/\/+/g, '/').replace(/\/$/, '') || '/'
        
        const node = findNode(normalizedPath)
        if (!node || node.type !== 'directory') {
          addCommand(cmd, `cd: ${targetPath}: No such file or directory`)
          return
        }

        setCurrentPath(normalizedPath)
        addCommand(cmd, '')
        break
      }

      case 'cat': {
        const filename = args[0]
        if (!filename) {
          addCommand(cmd, 'cat: missing file operand')
          return
        }

        const filePath = filename.startsWith('/') ? filename : `${currentPath}/${filename}`
        const node = findNode(filePath)
        
        if (!node) {
          addCommand(cmd, `cat: ${filename}: No such file or directory`)
          return
        }

        if (node.type !== 'file') {
          addCommand(cmd, `cat: ${filename}: Is a directory`)
          return
        }

        const content = node.content || ''
        addCommand(cmd, content)
        checkForFlags(content)
        break
      }

      case 'find': {
  const name = args.find((arg, i) => args[i-1] === '-name')
  const typeFilter = args.find((arg, i) => args[i-1] === '-type')
        
        const searchNode = (node: FileSystemNode, path: string): string[] => {
          let results: string[] = []
          
          if (name && node.name.includes(name.replace(/['"]/g, ''))) {
            if (!typeFilter || (typeFilter === 'f' && node.type === 'file') || (typeFilter === 'd' && node.type === 'directory')) {
              results.push(path + '/' + node.name)
            }
          }
          
          if (node.children) {
            for (const child of node.children) {
              results = results.concat(searchNode(child, path + '/' + node.name))
            }
          }
          
          return results
        }

        const results = searchNode(fileSystem, '')
        addCommand(cmd, results.join('\n'))
        break
      }

      case 'grep': {
        const pattern = args[0]
        const filename = args[1]
        
        if (!pattern || !filename) {
          addCommand(cmd, 'Usage: grep pattern filename')
          return
        }

        const filePath = filename.startsWith('/') ? filename : `${currentPath}/${filename}`
        const node = findNode(filePath)
        
        if (!node || node.type !== 'file') {
          addCommand(cmd, `grep: ${filename}: No such file or directory`)
          return
        }

        const content = node.content || ''
        const lines = content.split('\n')
        const matches = lines.filter(line => line.includes(pattern.replace(/['"]/g, '')))
        
        addCommand(cmd, matches.join('\n'))
        checkForFlags(matches.join('\n'))
        break
      }

      case 'pwd': {
        addCommand(cmd, currentPath)
        break
      }

      case 'whoami': {
        addCommand(cmd, 'user')
        break
      }

      case 'help': {
        const helpText = `Available commands:
ls [-la] [path]     - List directory contents
cd [path]           - Change directory  
cat [file]          - Display file contents
find [options]      - Search for files
grep [pattern] [file] - Search within files
pwd                 - Show current directory
whoami              - Show current user
help                - Show this help`
        addCommand(cmd, helpText)
        break
      }

      default: {
        addCommand(cmd, `${command}: command not found`)
        break
      }
    }
  }

  const handleCommandSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (currentCommand.trim()) {
      executeCommand(currentCommand.trim())
      setCurrentCommand('')
    }
  }

  const startGame = () => {
    setGameStarted(true)
    setTimeLeft(300)
    setFoundFlags([])
    setScore(0)
    setCommandHistory([])
  setCurrentPath('/home/user')
    addCommand('', 'Welcome to the CTF Challenge! Find all 7 hidden flags in the system.')
    addCommand('', 'Type "help" for available commands. Good luck!')
  }

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60)
    const secs = seconds % 60
    return `${mins}:${secs.toString().padStart(2, '0')}`
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
            <Flag className="w-8 h-8" />
            🚩 CTF Mini Challenge
            <Terminal className="w-8 h-8" />
          </h1>
          <p className="text-gray-600 mb-8">Navigate the file system and find hidden flags using Linux commands!</p>
          
          <div className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg p-8 border-2 border-[#ff8c00] max-w-2xl mx-auto">
            <h2 className="text-xl font-semibold mb-4">Mission Briefing</h2>
            <div className="text-left space-y-3 text-gray-700">
              <div className="flex items-start gap-3">
                <Search className="w-5 h-5 text-[#ff8c00] mt-0.5" />
                <p>Explore the Linux file system using terminal commands</p>
              </div>
              <div className="flex items-start gap-3">
                <Flag className="w-5 h-5 text-[#ff8c00] mt-0.5" />
                <p>Find 7 hidden flags scattered throughout the system</p>
              </div>
              <div className="flex items-start gap-3">
                <Clock className="w-5 h-5 text-[#ff8c00] mt-0.5" />
                <p>Complete the challenge within 5 minutes</p>
              </div>
              <div className="flex items-start gap-3">
                <Terminal className="w-5 h-5 text-[#ff8c00] mt-0.5" />
                <p>Use commands like ls, cat, find, grep to investigate</p>
              </div>
            </div>
            
            <div className="mt-6 text-sm text-gray-600 bg-white/50 p-4 rounded">
              <h3 className="font-semibold mb-2">Tips for Success:</h3>
              <ul className="space-y-1">
                <li>• Look for hidden files (use ls -la)</li>
                <li>• Check log files for suspicious activity</li>
                <li>• Examine source code comments</li>
                <li>• Search through command history</li>
                <li>• Investigate system configuration files</li>
              </ul>
            </div>
            
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={startGame}
              className="mt-6 px-8 py-3 bg-[#ff8c00] text-white rounded-lg font-medium hover:bg-[#ff6b35] transition-colors"
            >
              Start CTF Challenge
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
          <Flag className="w-8 h-8" />
          🚩 CTF Mini Challenge
          <Terminal className="w-8 h-8" />
        </h1>
      </motion.div>

      <div className="grid lg:grid-cols-4 gap-6">
        {/* Status Panel */}
        <motion.div 
          initial={{ x: -20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg p-6 border-2 border-[#ff8c00]"
        >
          <h2 className="text-lg font-semibold text-[#ff8c00] mb-4 flex items-center gap-2">
            <Trophy className="w-5 h-5" />
            Mission Status
          </h2>
          
          <div className="space-y-4">
            <div className="text-center p-3 bg-white/50 rounded-lg">
              <div className="text-2xl font-bold text-[#ff8c00]">{score}</div>
              <div className="text-sm text-gray-600">Score</div>
            </div>
            
            <div className="text-center p-3 bg-green-50 rounded-lg">
              <div className="text-xl font-bold text-green-600">{foundFlags.length}/7</div>
              <div className="text-xs text-gray-600">Flags Found</div>
            </div>
            
            <div className="text-center p-3 bg-red-50 rounded-lg">
              <div className="text-xl font-bold text-red-600">{formatTime(timeLeft)}</div>
              <div className="text-xs text-gray-600">Time Left</div>
            </div>
          </div>

          <div className="mt-4">
            <h3 className="font-semibold text-gray-700 mb-2">Flags Found:</h3>
            <div className="space-y-1">
              {foundFlags.map(flag => (
                <motion.div
                  key={flag}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="text-xs p-2 bg-green-100 text-green-800 rounded flex items-center gap-2"
                >
                  <CheckCircle className="w-3 h-3" />
                  <span className="font-mono truncate">{flag}</span>
                </motion.div>
              ))}
            </div>
          </div>

          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setShowHints(!showHints)}
            className="w-full mt-4 py-2 bg-yellow-100 hover:bg-yellow-200 text-yellow-800 rounded-lg transition-colors text-sm"
          >
            {showHints ? 'Hide' : 'Show'} Hints
          </motion.button>

          <AnimatePresence>
            {showHints && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="mt-2 p-3 bg-yellow-50 border border-yellow-200 rounded-lg text-xs"
              >
                <ul className="space-y-1 text-yellow-800">
                  <li>• Check hidden files with ls -la</li>
                  <li>• Look in /var/log for system logs</li>
                  <li>• Examine HTML source code</li>
                  <li>• Check bash history files</li>
                  <li>• Investigate /etc/passwd</li>
                  <li>• Search /etc/hosts file</li>
                  <li>• Look for temp files in /tmp</li>
                </ul>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Terminal */}
        <motion.div 
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          className="lg:col-span-3 bg-black rounded-lg p-6 shadow-lg"
        >
          <div className="flex items-center gap-2 mb-4">
            <div className="w-3 h-3 bg-red-500 rounded-full"></div>
            <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span className="ml-4 text-gray-400 text-sm">Terminal - CTF Challenge</span>
          </div>
          
          <div className="h-96 overflow-y-auto font-mono text-sm text-green-400 bg-gray-900 rounded p-4">
            {commandHistory.map((cmd) => (
              <div key={cmd.timestamp} className="mb-2">
                {cmd.command && (
                  <div className="text-green-300">
                    <span className="text-blue-400">user@ctf</span>
                    <span className="text-white">:</span>
                    <span className="text-purple-400">{currentPath}</span>
                    <span className="text-white">$ </span>
                    <span>{cmd.command}</span>
                  </div>
                )}
                {cmd.output && (
                  <pre className="text-gray-300 whitespace-pre-wrap">{cmd.output}</pre>
                )}
              </div>
            ))}
            
            <form onSubmit={handleCommandSubmit} className="flex">
              <span className="text-blue-400">user@ctf</span>
              <span className="text-white">:</span>
              <span className="text-purple-400">{currentPath}</span>
              <span className="text-white">$ </span>
              <input
                type="text"
                value={currentCommand}
                onChange={(e) => setCurrentCommand(e.target.value)}
                className="flex-1 bg-transparent text-green-400 outline-none ml-1"
                placeholder="Enter command..."
                disabled={!gameStarted || timeLeft === 0}
                autoFocus
              />
            </form>
          </div>
          
          <div className="mt-4 text-xs text-gray-400">
            Type &quot;help&quot; for available commands • Find flags in the format CTF{"{...}"}
          </div>
        </motion.div>
      </div>

      {/* Game Complete Modal */}
      <AnimatePresence>
        {(foundFlags.length === FLAGS.length || (!gameStarted && foundFlags.length > 0)) && (
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
              <h2 className="text-2xl font-bold text-center mb-4">
                {foundFlags.length === FLAGS.length ? 'Challenge Complete!' : 'Time\'s Up!'}
              </h2>
              <div className="text-center space-y-2">
                <p>Final Score: <span className="font-bold text-[#ff8c00]">{score}</span></p>
                <p>Flags Found: <span className="font-bold text-green-600">{foundFlags.length}/7</span></p>
                <p>Success Rate: <span className="font-bold text-blue-600">
                  {Math.round((foundFlags.length / FLAGS.length) * 100)}%
                </span></p>
                {foundFlags.length === FLAGS.length && (
                  <p className="text-green-600 font-bold">🎉 Perfect Score! Master Hacker! 🎉</p>
                )}
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