import { NextResponse } from "next/server"
import Parser from "rss-parser"

export const runtime = "nodejs"

interface SecurityNewsItem {
  id: string
  title: string
  source: string
  url: string
  publishedAt: string
  summary: string
  tags: string[]
}

const feeds = [
  {
    id: "cisa-alerts",
    label: "CISA Alerts",
    url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
  },
  {
    id: "us-cert",
    label: "US-CERT",
    url: "https://www.cisa.gov/uscert/ncas/alerts.xml",
  },
  {
    id: "security-week",
    label: "SecurityWeek",
    url: "https://feeds.feedburner.com/securityweek",
  },
]

const fallbackNews: SecurityNewsItem[] = [
  {
    id: "fallback-1",
    title: "Security news feeds temporarily unavailable",
    source: "OneStop-CYworld",
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories",
    publishedAt: new Date().toISOString(),
    summary: "We're experiencing issues connecting to security news sources. Check CISA directly for the latest cybersecurity alerts and advisories.",
    tags: ["status", "advisory"],
  },
]

function summarizeDescription(description: string | undefined): string {
  if (!description) return ""
  const cleaned = description
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\s+/g, " ")
    .trim()
  
  return cleaned.length > 280 ? `${cleaned.slice(0, 277)}…` : cleaned
}

export async function GET() {
  const parser = new Parser({
    timeout: 10000,
    headers: {
      'User-Agent': 'OneStop-CYworld/1.0 Security News Aggregator'
    }
  })

  try {
    const results = await Promise.allSettled(
      feeds.map(async (feed) => {
        try {
          const parsed = await parser.parseURL(feed.url)
          const items = parsed.items?.slice(0, 10) || []
          
          return items.map((item, index) => ({
            id: `${feed.id}-${Date.now()}-${index}`,
            title: item.title?.trim() || "Security Update",
            source: feed.label,
            url: item.link || feed.url,
            publishedAt: item.pubDate ? new Date(item.pubDate).toISOString() : new Date().toISOString(),
            summary: summarizeDescription(item.contentSnippet || item.content),
            tags: item.categories?.slice(0, 3) || ["security"],
          }))
        } catch (error) {
          console.warn(`Feed ${feed.id} failed:`, error)
          return []
        }
      })
    )

    const collected: SecurityNewsItem[] = []
    for (const result of results) {
      if (result.status === "fulfilled") {
        collected.push(...result.value)
      }
    }

    if (collected.length === 0) {
      return NextResponse.json({ ok: true, items: fallbackNews })
    }

    // Deduplicate by URL and sort by date
    const deduped = new Map<string, SecurityNewsItem>()
    for (const item of collected) {
      if (!deduped.has(item.url)) {
        deduped.set(item.url, item)
      }
    }

    const sorted = Array.from(deduped.values())
      .sort((a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime())
      .slice(0, 24)

    return NextResponse.json({ ok: true, items: sorted })
  } catch (error) {
    console.error("News API error:", error)
    return NextResponse.json({ ok: true, items: fallbackNews })
  }
}
