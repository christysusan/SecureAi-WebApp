import { NextResponse } from "next/server"

export const runtime = "nodejs"

const OSV_ENDPOINT = "https://api.osv.dev/v1/query"

const MAX_DEPENDENCIES = 50

const severityOrder = ["critical", "high", "medium", "low", "unknown"] as const

const severityScore: Record<(typeof severityOrder)[number], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
}

type Severity = (typeof severityOrder)[number]

type ManifestType = "requirements" | "package-json" | "go-mod" | "plaintext"

interface ScanRequest {
  manifestType: ManifestType
  content: string
}

interface Dependency {
  name: string
  version: string
  ecosystem: string
  reference?: string
}

interface DependencyVulnerability {
  id: string
  summary: string
  details: string
  severity: Severity
  severityScore: number
  published: string | null
  modified: string | null
  aliases: string[]
  references: string[]
  affectedRanges: string[]
  fixedVersion: string | null
  confidence: string | null
}

interface DependencyResult {
  dependency: Dependency
  vulnerabilities: DependencyVulnerability[]
  highestSeverity: Severity
  totalVulnerabilities: number
}

interface ScanResponse {
  stats: {
    totalDependencies: number
    vulnerableDependencies: number
    totalVulnerabilities: number
    highestSeverity: Severity | null
  }
  dependencies: DependencyResult[]
}

const isNonEmptyString = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0

const normalizeVersion = (version: string): string | null => {
  const cleaned = version.replace(/^[\^~<>=\s]*/, "").replace(/\s+.*$/, "").trim()
  if (!/(\d|v)/.test(cleaned)) return null
  if (cleaned === "latest" || cleaned === "*") return null
  return cleaned
}

const parseRequirements = (content: string): Dependency[] => {
  const result: Dependency[] = []
  const lines = content.split(/\r?\n/)
  for (const rawLine of lines) {
    const line = rawLine.split("#")[0]?.trim() ?? ""
    if (!line) continue

    const match = line.match(/^([A-Za-z0-9_.-]+)(?:\[.*\])?\s*==\s*([A-Za-z0-9_.-]+)/)
    if (!match) continue
    const name = match[1]
    const version = match[2]
    result.push({ name, version, ecosystem: "PyPI", reference: `${name}==${version}` })
  }
  return result
}

const parsePackageJson = (content: string): Dependency[] => {
  try {
    const parsed = JSON.parse(content) as Record<string, unknown>
    const buckets = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
    const collected: Dependency[] = []

    for (const bucket of buckets) {
      const section = parsed[bucket]
      if (!section || typeof section !== "object") continue
      for (const [name, rawVersion] of Object.entries(section as Record<string, unknown>)) {
        if (!isNonEmptyString(rawVersion)) continue
        const normalized = normalizeVersion(rawVersion)
        if (!normalized) continue
        collected.push({ name, version: normalized, ecosystem: "npm", reference: `${bucket}:${name}@${normalized}` })
      }
    }
    return collected
  } catch (error) {
    console.error("Failed to parse package.json", error)
    return []
  }
}

const parseGoMod = (content: string): Dependency[] => {
  const dependencies: Dependency[] = []
  const lines = content.split(/\r?\n/)
  let inRequireBlock = false

  const parseLine = (line: string) => {
    const noComment = line.split("//")[0]?.trim() ?? ""
    if (!noComment) return
    const [name, version] = noComment.split(/\s+/)
    if (!name || !version) return
    dependencies.push({ name, version, ecosystem: "Go", reference: `${name}@${version}` })
  }

  for (const rawLine of lines) {
    const line = rawLine.trim()
    if (line.startsWith("require (")) {
      inRequireBlock = true
      continue
    }
    if (inRequireBlock && line === ")") {
      inRequireBlock = false
      continue
    }
    if (line.startsWith("require ")) {
      parseLine(line.replace(/^require\s+/, ""))
      continue
    }
    if (inRequireBlock) {
      parseLine(line)
    }
  }

  return dependencies
}

const parsePlaintext = (content: string): Dependency[] => {
  const dependencies: Dependency[] = []
  const lines = content.split(/\r?\n/)
  for (const rawLine of lines) {
    const line = rawLine.split("#")[0]?.trim() ?? ""
    if (!line) continue

    const parts = line.split(":")
    if (parts.length !== 2) continue
    const [rawEco, rest] = parts
    const [name, versionPart] = rest.split("@")
    if (!rawEco || !name || !versionPart) continue
    const version = normalizeVersion(versionPart)
    if (!version) continue
    const ecosystem = rawEco.trim()
    dependencies.push({ name: name.trim(), version, ecosystem, reference: line })
  }
  return dependencies
}

const parseDependencies = (type: ManifestType, content: string): Dependency[] => {
  switch (type) {
    case "requirements":
      return parseRequirements(content)
    case "package-json":
      return parsePackageJson(content)
    case "go-mod":
      return parseGoMod(content)
    case "plaintext":
      return parsePlaintext(content)
    default:
      return []
  }
}

const severityFromScore = (score: number): Severity => {
  if (Number.isNaN(score)) return "unknown"
  if (score >= 9) return "critical"
  if (score >= 7) return "high"
  if (score >= 4) return "medium"
  if (score > 0) return "low"
  return "unknown"
}

const pickSeverity = (vulnerability: Record<string, unknown>): Severity => {
  const severityEntries = vulnerability.severity
  if (Array.isArray(severityEntries)) {
    const parsed = severityEntries
      .map((entry) => {
        if (!entry || typeof entry !== "object") return null
        const score = Number.parseFloat((entry as Record<string, unknown>).score as string)
        if (!Number.isFinite(score)) return null
        return severityFromScore(score)
      })
      .filter((value): value is Severity => Boolean(value))
    if (parsed.length > 0) {
      return parsed.sort((a, b) => severityScore[b] - severityScore[a])[0] ?? "unknown"
    }
  }

  const affected = vulnerability.affected
  if (Array.isArray(affected)) {
    for (const item of affected) {
      if (!item || typeof item !== "object") continue
      const ecoSpecific = (item as Record<string, unknown>).ecosystem_specific
      if (ecoSpecific && typeof ecoSpecific === "object") {
        const severity = (ecoSpecific as Record<string, unknown>).severity
        if (typeof severity === "string") {
          const normalized = severity.toLowerCase() as Severity
          if (severityOrder.includes(normalized)) return normalized
        }
      }
    }
  }

  return "medium"
}

const extractFixedVersions = (affected: unknown): string[] => {
  if (!Array.isArray(affected)) return []
  const fixes = new Set<string>()
  for (const entry of affected) {
    if (!entry || typeof entry !== "object") continue
    const ranges = (entry as Record<string, unknown>).ranges
    if (!Array.isArray(ranges)) continue
    for (const range of ranges) {
      if (!range || typeof range !== "object") continue
      const events = (range as Record<string, unknown>).events
      if (!Array.isArray(events)) continue
      for (const event of events) {
        if (!event || typeof event !== "object") continue
        const fixed = (event as Record<string, unknown>).fixed
        if (typeof fixed === "string" && fixed.trim().length > 0) {
          fixes.add(fixed.trim())
        }
      }
    }
  }
  return Array.from(fixes)
}

const extractRanges = (affected: unknown): string[] => {
  if (!Array.isArray(affected)) return []
  const ranges: string[] = []
  for (const entry of affected) {
    if (!entry || typeof entry !== "object") continue
    const item = entry as Record<string, unknown>
    if (Array.isArray(item.ranges)) {
      for (const range of item.ranges) {
        if (!range || typeof range !== "object") continue
        const events = (range as Record<string, unknown>).events
        if (!Array.isArray(events)) continue
        const labels: string[] = []
        for (const event of events) {
          if (!event || typeof event !== "object") continue
          const introduced = (event as Record<string, unknown>).introduced
          const fixed = (event as Record<string, unknown>).fixed
          if (typeof introduced === "string") {
            labels.push(`introduced ${introduced}`)
          }
          if (typeof fixed === "string") {
            labels.push(`fixed ${fixed}`)
          }
        }
        if (labels.length > 0) {
          ranges.push(labels.join(" → "))
        }
      }
    }
  }
  return ranges
}

const ensureArray = <T>(value: unknown): T[] => (Array.isArray(value) ? (value as T[]) : [])

const uniqueDependencies = (dependencies: Dependency[]): Dependency[] => {
  const map = new Map<string, Dependency>()
  for (const dependency of dependencies) {
    const key = `${dependency.ecosystem}:${dependency.name}`
    if (!map.has(key)) {
      map.set(key, dependency)
    }
  }
  return Array.from(map.values())
}

const queryOsv = async (dependency: Dependency): Promise<DependencyVulnerability[]> => {
  const body = {
    package: {
      name: dependency.name,
      ecosystem: dependency.ecosystem,
    },
    version: dependency.version,
  }

  const response = await fetch(OSV_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  })

  if (!response.ok) {
    const detail = await response.text().catch(() => "")
    throw new Error(`OSV query failed for ${dependency.name}@${dependency.version}: ${response.status} ${detail}`)
  }

  const payload = (await response.json()) as Record<string, unknown>
  const vulns = ensureArray<Record<string, unknown>>(payload.vulns)
  const results: DependencyVulnerability[] = []

  for (const vuln of vulns) {
    const id = typeof vuln.id === "string" ? vuln.id : "UNKNOWN"
    const summary = typeof vuln.summary === "string" ? vuln.summary : ""
    const details = typeof vuln.details === "string" ? vuln.details : ""
    const severity = pickSeverity(vuln)
    const aliases = ensureArray<string>(vuln.aliases).filter(isNonEmptyString)
    const references = ensureArray<Record<string, unknown>>(vuln.references)
      .map((reference) => {
        const url = (reference as Record<string, unknown>).url
        return typeof url === "string" ? url : null
      })
      .filter((url): url is string => Boolean(url))

    const affected = vuln.affected
    const fixes = extractFixedVersions(affected)
    const ranges = extractRanges(affected)

    const published = typeof vuln.published === "string" ? vuln.published : null
    const modified = typeof vuln.modified === "string" ? vuln.modified : null

    const severityValue = severityScore[severity] ?? 0

    let confidence: string | null = null
    const databaseSpecific = vuln.database_specific
    if (databaseSpecific && typeof databaseSpecific === "object") {
      const evidenceEntries = ensureArray<Record<string, unknown>>((databaseSpecific as Record<string, unknown>).evidence)
      const notes = evidenceEntries
        .map((entry) => {
          const note = (entry as Record<string, unknown>).note
          return typeof note === "string" ? note : null
        })
        .filter((entry): entry is string => Boolean(entry))
      if (notes.length > 0) {
        confidence = notes.join("; ")
      }
    }

    results.push({
      id,
      summary,
      details,
      severity,
      severityScore: severityValue,
      published,
      modified,
      aliases,
      references,
      affectedRanges: ranges,
      fixedVersion: fixes[0] ?? null,
      confidence,
    })
  }

  return results.sort((a, b) => b.severityScore - a.severityScore)
}

const buildResponse = (dependencies: Dependency[], results: Map<string, DependencyVulnerability[]>): ScanResponse => {
  const dependencyResults: DependencyResult[] = []

  for (const dependency of dependencies) {
    const key = `${dependency.ecosystem}:${dependency.name}`
    const vulns = results.get(key) ?? []
    const highestSeverity = vulns[0]?.severity ?? "unknown"
    dependencyResults.push({
      dependency,
      vulnerabilities: vulns,
      highestSeverity,
      totalVulnerabilities: vulns.length,
    })
  }

  const vulnerableDependencies = dependencyResults.filter((entry) => entry.totalVulnerabilities > 0)
  const allVulnerabilities = vulnerableDependencies.flatMap((entry) => entry.vulnerabilities)
  const highestOverall = vulnerableDependencies.length > 0 ? vulnerableDependencies.reduce((current, entry) => {
    if (!severityOrder.includes(entry.highestSeverity)) return current
    if (!severityOrder.includes(current)) return entry.highestSeverity
    return severityScore[entry.highestSeverity] > severityScore[current] ? entry.highestSeverity : current
  }, vulnerableDependencies[0]?.highestSeverity ?? "unknown") : null

  return {
    stats: {
      totalDependencies: dependencies.length,
      vulnerableDependencies: vulnerableDependencies.length,
      totalVulnerabilities: allVulnerabilities.length,
      highestSeverity: highestOverall,
    },
    dependencies: dependencyResults.sort((a, b) => (b.highestSeverity ? severityScore[b.highestSeverity] : 0) - (a.highestSeverity ? severityScore[a.highestSeverity] : 0)),
  }
}

export async function POST(req: Request) {
  const body = (await req.json().catch(() => null)) as Partial<ScanRequest> | null
  if (!body) {
    return NextResponse.json({ error: "INVALID_REQUEST", message: "Invalid JSON payload." }, { status: 400 })
  }

  const manifestType = body.manifestType as ManifestType
  const content = typeof body.content === "string" ? body.content : ""

  if (!manifestType || !content.trim()) {
    return NextResponse.json(
      { error: "MISSING_INPUT", message: "Provide a manifest type and dependency content." },
      { status: 400 },
    )
  }

  const parsedDependencies = uniqueDependencies(parseDependencies(manifestType, content)).slice(0, MAX_DEPENDENCIES)

  if (parsedDependencies.length === 0) {
    return NextResponse.json(
      {
        error: "NO_DEPENDENCIES",
        message:
          manifestType === "package-json"
            ? "No pinned dependencies found. Provide exact versions (no ^ or ~ ranges)."
            : "No dependencies could be parsed from the provided content.",
      },
      { status: 400 },
    )
  }

  try {
    const results = new Map<string, DependencyVulnerability[]>()

    for (const dependency of parsedDependencies) {
      const vulns = await queryOsv(dependency).catch((error) => {
        console.error("OSV query failed", error)
        return [] as DependencyVulnerability[]
      })
      results.set(`${dependency.ecosystem}:${dependency.name}`, vulns)
    }

    return NextResponse.json(buildResponse(parsedDependencies, results))
  } catch (error) {
    console.error("Dependency scan failed", error)
    return NextResponse.json(
      {
        error: "SCAN_FAILED",
        message: "Unable to complete the dependency vulnerability scan.",
        detail: error instanceof Error ? error.message : String(error),
      },
      { status: 500 },
    )
  }
}
