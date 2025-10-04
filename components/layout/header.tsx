"use client"
import Link from "next/link"
import { AnimatePresence, motion } from "framer-motion"
import { Menu, X } from "lucide-react"
import { usePathname } from "next/navigation"
import { useEffect, useState } from "react"

import { ThemeToggle } from "@/components/theme/theme-toggle"
import { cn } from "@/lib/utils"

export function Header() {
  const [time, setTime] = useState<string>(new Date().toLocaleTimeString())
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false)
  const pathname = usePathname()

  useEffect(() => {
    const id = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    setIsMobileNavOpen(false)
  }, [pathname])

  useEffect(() => {
    if (typeof document === "undefined") return
    if (isMobileNavOpen) {
      const original = document.body.style.overflow
      document.body.style.overflow = "hidden"
      return () => {
        document.body.style.overflow = original
      }
    }
    return
  }, [isMobileNavOpen])

  const nav = [
    { href: "/", label: "Home" },
    { href: "/scan", label: "Basic Scan" },
    { href: "/ai-assess", label: "AI Assess" },
    { href: "/pass-strength", label: "Pass Strength" },
    { href: "/dependency-scanner", label: "Dependency Scanner" },
    { href: "/games", label: "Games" },
    { href: "/config", label: "Config" },
    // { href: "/docs", label: "Docs" },
  ]

  return (
    <header className="sticky top-0 z-40 w-full border-b border-border bg-surface/80 backdrop-blur">
      <div className="mx-auto max-w-6xl px-4">
        <div className="flex h-14 items-center justify-between gap-4">
          <Link href="/" className="flex-shrink-0 font-mono text-brand uppercase tracking-wider">
            {"┌ SecureAI-Code Web ┐"}
          </Link>
          <nav className="hidden flex-1 items-center justify-center gap-6 md:flex">
            {nav.map((item) => {
              const isActive = pathname === item.href
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "rounded px-3 py-1 text-sm transition-colors whitespace-nowrap",
                    isActive ? "bg-brand/10 text-brand" : "text-foreground/80 hover:text-foreground",
                    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand",
                  )}
                >
                  {item.label}
                </Link>
              )
            })}
          </nav>
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-border bg-surface/60 text-foreground transition hover:border-brand hover:text-brand md:hidden"
              aria-label={isMobileNavOpen ? "Close navigation" : "Open navigation"}
              onClick={() => setIsMobileNavOpen((prev) => !prev)}
            >
              {isMobileNavOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
            </button>
            <ThemeToggle />
            <div className="hidden whitespace-nowrap font-mono text-xs text-foreground/70 sm:block">{time}</div>
          </div>
        </div>
      </div>
      <AnimatePresence>
        {isMobileNavOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-40 bg-surface/95 backdrop-blur-md md:hidden"
          >
            <motion.div
              initial={{ opacity: 0, y: -16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -16 }}
              transition={{ duration: 0.2 }}
              className="mx-auto mt-24 w-full max-w-sm px-4"
            >
              <div className="flex flex-col gap-3 rounded-2xl border border-border bg-card/90 p-6 shadow-lg">
                <p className="text-xs uppercase tracking-wide text-foreground/60">Navigate</p>
                {nav.map((item) => {
                  const isActive = pathname === item.href
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={cn(
                        "flex items-center justify-between rounded-xl px-4 py-3 text-sm font-medium transition",
                        isActive
                          ? "bg-brand text-white shadow-lg shadow-brand/30"
                          : "bg-surface/80 text-foreground hover:bg-brand/10 hover:text-brand",
                      )}
                    >
                      <span>{item.label}</span>
                      <span className="text-xs text-foreground/60">{item.href}</span>
                    </Link>
                  )
                })}
                <div className="mt-2 rounded-xl border border-border bg-surface/80 p-4 text-xs text-foreground/70">
                  <p className="font-semibold text-foreground">Current time</p>
                  <p className="mt-1 font-mono text-sm">{time}</p>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  )
}
