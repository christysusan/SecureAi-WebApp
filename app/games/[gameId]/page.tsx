import { Header } from "@/components/layout/header"
import { TerminalBox } from "@/components/layout/terminal-box"
import SnakeQuiz from "@/components/games/snake-quiz"
import PasswordCrackerGame from "@/components/games/password-cracker"
import PhishingDetectorGame from "@/components/games/phishing-detector"
import FirewallDefenderGame from "@/components/games/firewall-defender"
import EncryptionPuzzleGame from "@/components/games/encryption-puzzle"
import CTFMiniGame from "@/components/games/ctf-mini"
import LogAnalysisGame from "@/components/games/log-analysis"
import IncidentResponseSimulator from "@/components/games/incident-response"

const gameComponents = {
  snake: SnakeQuiz,
  password: PasswordCrackerGame,
  phishing: PhishingDetectorGame,
  firewall: FirewallDefenderGame,
  encryption: EncryptionPuzzleGame,
  ctf: CTFMiniGame,
  logs: LogAnalysisGame,
  incident: IncidentResponseSimulator,
}

export default function GamePage({ params }: { params: { gameId: string } }) {
  const GameComponent = gameComponents[params.gameId as keyof typeof gameComponents]

  if (!GameComponent) {
    return (
      <>
        <Header />
        <main className="mx-auto max-w-6xl px-4 py-8">
          <TerminalBox title={`🎮 Game: ${params.gameId}`}>
            <p className="text-sm text-muted">
              Game not found. Available games: snake, password, phishing, firewall, encryption, ctf, logs, incident
            </p>
          </TerminalBox>
        </main>
      </>
    )
  }

  return (
    <>
      <Header />
      <main className="mx-auto max-w-full px-4 py-8">
        <GameComponent />
      </main>
    </>
  )
}
