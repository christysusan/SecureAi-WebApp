export interface SecurityNewsItem {
  id: string
  title: string
  source: string
  url: string
  publishedAt: string
  summary: string
  tags: string[]
}

interface RemoteFeedItem {
  title: string
  pubDate?: string
  link?: string
  description?: string
  categories?: string[]
  author?: string
}

const feeds = [
  {
    id: "gn-cybersecurity",
    label: "Google News: Cybersecurity",
    rss: "https://news.google.com/rss/search?q=cybersecurity&hl=en-US&gl=US&ceid=US:en",
  },
  {
    id: "gn-cve",
    label: "Google News: CVE & Zero-Day",
    rss: "https://news.google.com/rss/search?q=CVE%20OR%20%22critical%20vulnerability%22%20OR%20%22zero-day%22&hl=en-US&gl=US&ceid=US:en",
  },
  {
    id: "gn-ransomware",
    label: "Google News: Ransomware & Breaches",
    rss: "https://news.google.com/rss/search?q=ransomware%20OR%20%22data%20breach%22&hl=en-US&gl=US&ceid=US:en",
  },
]

const RSS_TO_JSON_ENDPOINT = "https://api.rss2json.com/v1/api.json"

const summaryFromDescription = (description: string | undefined): string => {
  if (!description) return ""
  const sanitized = description
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim()

  return sanitized.length > 280 ? `${sanitized.slice(0, 277)}…` : sanitized
}

const normalizeItem = (item: RemoteFeedItem, source: string, sourceId: string): SecurityNewsItem => {
  const publishedAt = item.pubDate ? new Date(item.pubDate).toISOString() : new Date().toISOString()

  const baseId = `${sourceId}-${item.link ?? item.title ?? Math.random().toString(36).slice(2)}`

  const tags = Array.isArray(item.categories)
    ? item.categories
        .map((category) => category.trim())
        .filter((category) => category.length > 0)
        .slice(0, 4)
    : []

  if (item.author && !tags.includes(item.author)) {
    tags.push(item.author)
  }

  return {
    id: baseId,
    title: item.title?.trim() ?? "Security update",
    source,
    url: item.link ?? "https://news.google.com/search?q=cybersecurity&hl=en-US&gl=US&ceid=US:en",
    publishedAt,
    summary: summaryFromDescription(item.description),
    tags,
  }
}

const fallbackNews: SecurityNewsItem[] = [
  {
    id: "fallback-1",
    title: "Security bulletin feed temporarily unavailable",
    source: "OneStop-CYworld",
    url: "https://news.google.com/search?q=cybersecurity&hl=en-US&gl=US&ceid=US:en",
    publishedAt: new Date().toISOString(),
    summary:
      "We couldn’t refresh the external security news feeds right now. Check Google News for the latest cybersecurity headlines while our feed reconnects.",
    tags: ["status", "advisory"],
  },
]

export async function fetchSecurityNews(limit = 18): Promise<SecurityNewsItem[]> {
  const apiKey = (typeof process !== "undefined" && process.env && process.env.RSS2JSON_API_KEY) || ""

  try {
    const settled = await Promise.allSettled(
      feeds.map(async (feed) => {
        const url = new URL(RSS_TO_JSON_ENDPOINT)
        url.searchParams.set("rss_url", feed.rss)
        url.searchParams.set("count", String(Math.min(limit, 20)))
        if (apiKey) url.searchParams.set("api_key", apiKey)

        const response = await fetch(url.toString(), {
          headers: {
            "User-Agent": "OneStop-CYworld News Service",
          },
          next: { revalidate: 60 * 30 },
        })

        if (!response.ok) {
          // Don’t fail the whole aggregation if a single feed errors (e.g., 4xx/5xx or rate limit)
          console.warn(`News feed skipped: ${feed.id} responded with ${response.status}`)
          return []
        }

        const payload = (await response.json()) as { items?: RemoteFeedItem[] }
        const items = Array.isArray(payload.items) ? payload.items : []
        return items.slice(0, limit).map((item) => normalizeItem(item, feed.label, feed.id))
      }),
    )

    const collected: SecurityNewsItem[] = []
    for (const res of settled) {
      if (res.status === "fulfilled") {
        collected.push(...res.value)
      } else {
        console.warn("News feed failed:", res.reason)
      }
    }

    if (collected.length === 0) {
      return fallbackNews
    }

    const deduped = new Map<string, SecurityNewsItem>()
    for (const item of collected) {
      if (!deduped.has(item.url)) deduped.set(item.url, item)
    }

    return Array.from(deduped.values())
      .sort((a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime())
      .slice(0, limit)
  } catch (error) {
    console.error("Failed to load security news", error)
    return fallbackNews
  }
}

export function groupNewsByDate(items: SecurityNewsItem[]): Array<{ date: string; items: SecurityNewsItem[] }> {
  const bucket = new Map<string, SecurityNewsItem[]>()

  for (const item of items) {
    const key = item.publishedAt.slice(0, 10)
    const entry = bucket.get(key)
    if (entry) {
      entry.push(item)
    } else {
      bucket.set(key, [item])
    }
  }

  return Array.from(bucket.entries())
    .map(([date, groupedItems]) => ({
      date,
      items: groupedItems.sort((a, b) => (a.publishedAt > b.publishedAt ? -1 : 1)),
    }))
    .sort((a, b) => (a.date > b.date ? -1 : 1))
}
