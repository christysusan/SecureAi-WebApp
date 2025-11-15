"use client"

import { useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { CalendarDays, ExternalLink, RefreshCcw, ShieldAlert } from "lucide-react"

import { Header } from "@/components/layout/header"
import { TerminalBox } from "@/components/layout/terminal-box"
import type { SecurityNewsItem } from "@/lib/news"
import { groupNewsByDate } from "@/lib/news"
import { cn } from "@/lib/utils"

const formatDate = (value: string) =>
  new Intl.DateTimeFormat("en", {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value))

function TagPill({ label }: { label: string }) {
  return (
    <span className="rounded-full border border-brand/40 bg-brand/10 px-2 py-1 text-[11px] uppercase tracking-wide text-brand/90">
      {label}
    </span>
  )
}

function NewsCard({
  title,
  summary,
  source,
  url,
  publishedAt,
  tags,
}: SecurityNewsItem) {
  return (
    <article className="space-y-3 rounded-xl border border-border bg-card/80 p-5 shadow-sm transition hover:border-brand/70">
      <div className="flex items-center justify-between gap-4">
        <span className="text-xs uppercase tracking-wide text-muted-foreground">{source}</span>
        <span className="flex items-center gap-1 text-xs text-muted-foreground/80">
          <CalendarDays className="h-3.5 w-3.5" />
          {formatDate(publishedAt)}
        </span>
      </div>
      <h3 className="text-lg font-semibold text-foreground">
        <Link href={url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 hover:text-brand">
          {title}
          <ExternalLink className="h-4 w-4" />
        </Link>
      </h3>
      {summary ? <p className="text-sm leading-relaxed text-muted-foreground">{summary}</p> : null}
      {tags.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {tags.map((tag) => (
            <TagPill key={`${title}-${tag}`} label={tag} />
          ))}
        </div>
      ) : null}
    </article>
  )
}

export default function SecurityNewsPage() {
  const [newsItems, setNewsItems] = useState<SecurityNewsItem[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    const loadNews = async () => {
      try {
        const res = await fetch("/api/news", { cache: "no-store" })
        if (!res.ok) {
          throw new Error(`News endpoint returned status ${res.status}`)
        }
        const payload = (await res.json()) as { ok: boolean; items?: SecurityNewsItem[] }
        if (!cancelled) {
          setNewsItems(Array.isArray(payload.items) ? payload.items : [])
          setError(null)
        }
      } catch (err) {
        console.error("Failed to fetch news", err)
        if (!cancelled) {
          setError("We couldn’t reach the security feeds just now. Try again shortly.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
        }
      }
    }

    loadNews()

    const interval = setInterval(loadNews, 30 * 60 * 1000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  const grouped = useMemo(() => groupNewsByDate(newsItems), [newsItems])
  const featured = useMemo(() => newsItems.slice(0, 3), [newsItems])

  return (
    <>
      <Header />
      <main className="relative mx-auto max-w-7xl px-4 py-10 text-foreground">
        <section className="mb-10 text-center">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-brand/40 bg-brand/10 px-4 py-2 text-xs font-semibold uppercase tracking-widest text-brand">
            <ShieldAlert className="h-4 w-4" />
            Live Security Intelligence Feed
          </div>
          <h1 className="mb-4 text-4xl font-bold tracking-tight text-foreground sm:text-5xl">Security News & Advisories</h1>
          <p className="mx-auto max-w-3xl text-base leading-relaxed text-muted-foreground sm:text-lg">
            Stay ahead of critical vulnerabilities,
            exploits, and incident response guidance.
          </p>
        </section>

        {isLoading ? (
          <section className="mb-12 grid gap-6 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, index) => (
              <div key={index} className="rounded-xl border border-border bg-card/60 p-6">
                <div className="mb-3 h-4 w-24 animate-pulse rounded bg-muted" />
                <div className="mb-2 h-6 w-full animate-pulse rounded bg-muted" />
                <div className="mb-4 h-6 w-3/4 animate-pulse rounded bg-muted" />
                <div className="space-y-2">
                  <div className="h-3 w-full animate-pulse rounded bg-muted" />
                  <div className="h-3 w-5/6 animate-pulse rounded bg-muted" />
                  <div className="h-3 w-2/3 animate-pulse rounded bg-muted" />
                </div>
              </div>
            ))}
          </section>
        ) : null}

        {error ? (
          <TerminalBox title="Feed status" className="mb-10">
            <p className="text-sm text-muted-foreground">{error}</p>
          </TerminalBox>
        ) : null}

        {!isLoading && featured.length > 0 ? (
          <section className="mb-12 grid gap-6 lg:grid-cols-3">
            {featured.map((item) => (
              <div key={item.id} className="lg:col-span-1">
                <NewsCard {...item} />
              </div>
            ))}
          </section>
        ) : null}

        {!isLoading && grouped.length > 0 ? (
          <section className="space-y-8">
            {grouped.map((group) => (
              <TerminalBox
                key={group.date}
                title={new Intl.DateTimeFormat("en", { dateStyle: "full" }).format(new Date(group.date))}
                className="space-y-6"
              >
                <div className={cn("grid gap-6", group.items.length > 2 ? "md:grid-cols-2" : "")}
                >
                  {group.items.map((item) => (
                    <NewsCard key={item.id} {...item} />
                  ))}
                </div>
              </TerminalBox>
            ))}
          </section>
        ) : null}
      </main>
    </>
  )
}
