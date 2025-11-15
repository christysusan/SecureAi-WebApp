"use client"

import { createContext, useContext, type ReactNode, type ReactElement } from "react"

// Simplified theme context - light mode only
interface ThemeContextValue {
  theme: "light"
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined)

export function ThemeProvider({ children }: { children: ReactNode }): ReactElement {
  const value: ThemeContextValue = { theme: "light" }
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error("useTheme must be used within a ThemeProvider")
  }
  return context
}
