import { create } from "zustand"
import type { AppState, ScanResult } from "@/types"

export const useAppStore = create<AppState>((set) => ({
  currentScan: {
    target: "",
    status: "idle",
    progress: 0,
    results: [] as ScanResult[],
  },
  aiConfig: {
    apiKey: "",
    model: "Gemini 2.5",
    analysisDepth: "basic",
  },
  games: {},
  theme: "dark",
  sidebarOpen: false,
  currentPage: "/",
  setScan: (partial) => set((s) => ({ currentScan: { ...s.currentScan, ...partial } })),
  setAI: (partial) => set((s) => ({ aiConfig: { ...s.aiConfig, ...partial } })),
  setTheme: (theme) => set({ theme }),
  setPage: (p) => set({ currentPage: p }),
}))
