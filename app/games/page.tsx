"use client"

import Link from "next/link"
import { motion } from "framer-motion"
import { ArrowRight } from "lucide-react"

import { BackgroundOrnaments } from "@/components/decor/background-ornaments"
import { Header } from "@/components/layout/header"
import { TerminalBox } from "@/components/layout/terminal-box"

const games = [
  {
    id: "snake",
    title: "CyberSnake Quiz",
    desc: "Learn cybersecurity through an interactive snake game with technical questions",
    difficulty: "Beginner",
    category: "Quiz Game",
  },
  {
    id: "password",
    title: "Password Defense",
    desc: "Defend against password attacks by creating stronger passwords",
    difficulty: "Intermediate",
    category: "Defense",
  },
  {
    id: "phishing",
    title: "Phishing Detective",
    desc: "Analyze emails to identify phishing attempts and social engineering",
    difficulty: "Intermediate",
    category: "Analysis",
  },
  {
    id: "firewall",
    title: "Firewall Defense",
    desc: "Configure firewall rules to block malicious network traffic",
    difficulty: "Advanced",
    category: "Network",
  },
  {
    id: "encryption",
    title: "Crypto Puzzles",
    desc: "Solve encryption challenges and learn cryptographic principles",
    difficulty: "Advanced",
    category: "Cryptography",
  },
  {
    id: "ctf",
    title: "CTF Mini",
    desc: "Navigate file systems and find hidden flags in capture-the-flag style",
    difficulty: "Expert",
    category: "Investigation",
  },
  {
    id: "logs",
    title: "Threat Hunter Lab",
    desc: "Inspect live telemetry, flag malicious events, and maintain SOC accuracy",
    difficulty: "Advanced",
    category: "Analysis",
  },
  {
    id: "incident",
    title: "Incident Response Simulator",
    desc: "Lead crisis decisions across ransomware, phishing, and cloud breaches",
    difficulty: "Expert",
    category: "Strategy",
  },
]

const difficultyColors = {
  Beginner: "bg-emerald-50 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-100",
  Intermediate: "bg-amber-50 text-amber-800 dark:bg-amber-900/30 dark:text-amber-100",
  Advanced: "bg-orange-50 text-orange-800 dark:bg-orange-900/30 dark:text-orange-100",
  Expert: "bg-rose-50 text-rose-800 dark:bg-rose-900/30 dark:text-rose-100",
}

export default function GamesPage() {
  return (
    <>
      <Header />
      <main className="relative mx-auto max-w-6xl px-4 py-8">
        <BackgroundOrnaments />
        
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8 text-center"
        >
          <h1 className="mb-4 text-4xl font-semibold text-foreground">Explore Cybersecurity Simulations</h1>
          <p className="mx-auto max-w-2xl text-lg text-foreground/80">
            Master cybersecurity concepts through interactive games and hands-on challenges. 
            Each game teaches real-world security principles through engaging gameplay.
          </p>
        </motion.div>

        <TerminalBox title="Choose Your Challenge" className="mb-6">
          <div className="grid gap-6 sm:grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
            {games.map((game, index) => (
              <motion.div
                key={game.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <Link
                  href={`/games/${game.id}`}
                  className="block h-full"
                >
                  <motion.div
                    whileHover={{
                      scale: 1.01,
                      boxShadow: "0 18px 45px -15px rgba(15, 23, 42, 0.25)",
                    }}
                    whileTap={{ scale: 0.98 }}
                    className="group relative flex h-full flex-col rounded-xl border border-border bg-card p-6 transition-all duration-200 hover:border-brand"
                  >
                    <div className="mb-4 flex items-start justify-between">
                      <h3 className="text-xl font-semibold text-foreground">{game.title}</h3>
                      <span
                        className={`rounded-full px-2 py-1 text-xs font-medium ${difficultyColors[game.difficulty as keyof typeof difficultyColors]}`}
                      >
                        {game.difficulty}
                      </span>
                    </div>
                    
                    <p className="mb-6 text-sm leading-relaxed text-foreground/80">{game.desc}</p>
                    
                    <div className="mt-auto flex items-center justify-between">
                      <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-1 text-xs font-medium text-foreground/80">
                        {game.category}
                      </span>
                      <motion.span
                        className="inline-flex items-center gap-2 text-brand"
                        whileHover={{ x: 6 }}
                      >
                        <span className="text-sm font-medium">Play now</span>
                        <ArrowRight className="h-4 w-4" aria-hidden="true" />
                      </motion.span>
                    </div>
                  </motion.div>
                </Link>
              </motion.div>
            ))}
          </div>
          
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.8 }}
            className="mt-8 rounded-xl border border-border bg-muted/40 p-6 text-center"
          >
            <h3 className="mb-2 text-lg font-semibold text-foreground">Learning through play</h3>
            <p className="mx-auto max-w-3xl text-sm text-foreground/80">
              Each game is designed to teach specific cybersecurity concepts through hands-on experience. 
              Progress through difficulty levels, earn points, and master real-world security skills. 
              Perfect for security professionals, students, and anyone interested in cybersecurity!
            </p>
          </motion.div>
        </TerminalBox>
      </main>
    </>
  )
}
