export interface ScanResult {
  id: string
  severity: "critical" | "high" | "medium" | "low"
  file: string
  line: number
  message: string
  snippet?: string
}

export interface AIVulnerability {
  id: string
  title: string
  description: string
  severity: "critical" | "high" | "medium" | "low"
  recommendations: string[]
}

export interface AppState {
  currentScan: {
    target: string
    status: "idle" | "running" | "completed" | "error"
    progress: number
    results: ScanResult[]
  }
  aiConfig: {
    apiKey: string
    model: string
    analysisDepth: "basic" | "deep"
  }
  theme: "dark" | "light"
  sidebarOpen: boolean
  currentPage: string

  // actions
  setScan?: (partial: Partial<AppState["currentScan"]>) => void
  setAI?: (partial: Partial<AppState["aiConfig"]>) => void
  setTheme?: (t: AppState["theme"]) => void
  setPage?: (p: string) => void
}
