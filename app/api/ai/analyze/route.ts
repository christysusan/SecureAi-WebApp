import { NextResponse } from "next/server"

export const runtime = "nodejs"

type Provider = "openai" | "anthropic" | "gemini"
type Severity = "critical" | "high" | "medium" | "low"
type AnalysisMode = "code" | "dependencies"

interface AnalysisRequestBody {
  apiKey: string
  provider: Provider
  fileName: string
  code: string
  confidence?: number
  mode?: AnalysisMode
}

interface RawAiResponse {
  summary?: unknown
  overview?: unknown
  riskSummary?: unknown
  vulnerabilities?: unknown
  findings?: unknown
  issues?: unknown
  tokensUsed?: unknown
}

interface NormalizedVulnerability {
  id: string
  title: string
  severity: Severity
  line: number | null
  endLine: number | null
  rule: string
  summary: string
  remediation: string
  references: string[]
  codeExcerpt: string | null
}

const SUPPORTED_PROVIDERS: Provider[] = ["openai", "anthropic", "gemini"]

const DEFAULT_MODELS: Record<Provider, string> = {
  openai: "gpt-4o-mini",
  anthropic: "claude-3-5-sonnet-latest",
  gemini: "gemini-2.5-flash",
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"]

const normalizeSeverity = (value: unknown): Severity => {
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase()
    if (normalized.includes("critical")) return "critical"
    if (normalized.includes("high")) return "high"
    if (normalized.includes("medium")) return "medium"
    if (normalized.includes("low")) return "low"
  }
  if (typeof value === "number") {
    if (value >= 8) return "critical"
    if (value >= 6) return "high"
    if (value >= 3) return "medium"
    return "low"
  }
  return "medium"
}

const extractJsonObject = (content: string): RawAiResponse => {
  const firstBrace = content.indexOf("{")
  const lastBrace = content.lastIndexOf("}")
  if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) {
    throw new Error("AI response did not contain a JSON object")
  }

  const jsonSlice = content.slice(firstBrace, lastBrace + 1)
  return JSON.parse(jsonSlice) as RawAiResponse
}

const ensureString = (value: unknown): string | null => {
  if (typeof value === "string") {
    const trimmed = value.trim()
    return trimmed.length > 0 ? trimmed : null
  }
  return null
}

const ensureStringArray = (value: unknown): string[] => {
  if (!Array.isArray(value)) return []
  return value
    .map((entry) => ensureString(entry))
    .filter((entry): entry is string => Boolean(entry))
}

const ensureNumber = (value: unknown): number | null => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value
  }
  if (typeof value === "string") {
    const parsed = Number.parseFloat(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return null
}

const normalizeVulnerabilities = (raw: RawAiResponse, fileName: string): NormalizedVulnerability[] => {
  const candidates = [raw.vulnerabilities, raw.findings, raw.issues].find(Array.isArray) as unknown[] | undefined
  if (!candidates) return []

  return candidates
    .map((entry, index) => {
      if (typeof entry !== "object" || entry === null) return null
      const source = entry as Record<string, unknown>

      const id = ensureString(source.id) ?? ensureString(source.identifier) ?? `finding-${index + 1}`
      const title =
        ensureString(source.title) ??
        ensureString(source.name) ??
        ensureString(source.type) ??
        `Potential issue in ${fileName}`
      const rule =
        ensureString(source.rule) ??
        ensureString(source.cwe) ??
        ensureString(source.classification) ??
        "Unclassified"

      const summary =
        ensureString(source.summary) ??
        ensureString(source.description) ??
        ensureString(source.details) ??
        "The model flagged this code for further review."

      const remediation =
        ensureString(source.remediation) ??
        ensureString(source.fix) ??
        ensureStringArray(source.recommendations).join("\n") ??
        "Review business logic and apply secure coding best practices."

      const severity = normalizeSeverity(source.severity)

      const lineCandidates = [source.line, source.lineNumber, source.startLine, source.line_start, source.position]
      const line = lineCandidates.map(ensureNumber).find((value): value is number => value != null)

      const endLineCandidates = [source.endLine, source.line_end, source.end_line]
      const endLine = endLineCandidates.map(ensureNumber).find((value): value is number => value != null)

      const references = ensureStringArray(source.references ?? source.links)

      const codeExcerpt =
        ensureString(source.code_excerpt) ??
        ensureString(source.codeSnippet) ??
        ensureString(source.snippet) ??
        ensureString(source.code)

      return {
        id,
        title,
        severity,
        line: line ?? null,
        endLine: endLine ?? null,
        rule,
        summary,
        remediation,
        references,
        codeExcerpt: codeExcerpt ?? null,
      }
    })
    .filter((entry): entry is NormalizedVulnerability => Boolean(entry))
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
}

const buildPrompt = (fileName: string, code: string, confidence: number | undefined, mode: AnalysisMode): string => {
  const guardrail = confidence ? `The user selected an analysis confidence threshold of ${confidence}. Honor this by being precise.` : ""

  if (mode === "dependencies") {
    return `You are SecureAI, a dependency remediation assistant. You will receive JSON describing dependencies, their versions, and known vulnerabilities (including CVE identifiers, severity, and available fixes).
Respond with JSON only using the exact shape:
{
  "summary": string,
  "vulnerabilities": [
    {
      "id": string,
      "title": string,
      "severity": "critical" | "high" | "medium" | "low",
      "rule": string,
      "line": number | null,
      "endLine": number | null,
      "summary": string,
      "remediation": string,
      "references": string[],
      "code_excerpt": string | null
    }
  ]
}
For each entry, recommend precise upgrade actions (e.g., \"Upgrade library@fixed_version\"), optional PR subject/body text, and extra context in the remediation field. Leave line information as null.
${guardrail}

Dependency vulnerability data (${fileName}):
<json>
${code}
</json>`
  }

  return `You are SecureAI, a security auditing assistant. Assess the provided code for vulnerabilities, insecure patterns, or design flaws.
Output JSON only with the following shape:
{
  "summary": string,
  "vulnerabilities": [
    {
      "id": string,
      "title": string,
      "severity": "critical" | "high" | "medium" | "low",
      "rule": string,
      "line": number | null,
      "endLine": number | null,
      "summary": string,
      "remediation": string,
      "references": string[],
      "code_excerpt": string
    }
  ]
}
Always map findings to the most relevant CWE identifier in the "rule" property.
Use 1-based line numbers. If a line cannot be determined, set it to null.
${guardrail}

Analyze the file ${fileName}:
<code>
${code}
</code>`
}

const callOpenAI = async (params: { apiKey: string; prompt: string; model: string }) => {
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${params.apiKey}`,
    },
    body: JSON.stringify({
      model: params.model,
      temperature: 0.1,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: "You are SecureAI, a precise application security analyst.",
        },
        {
          role: "user",
          content: params.prompt,
        },
      ],
    }),
  })

  if (!response.ok) {
    const detail = await response.text().catch(() => "")
    throw new Error(`OpenAI request failed: ${response.status} ${detail}`)
  }

  const payload = (await response.json()) as {
    choices?: Array<{ message?: { content?: string } }>
    usage?: { total_tokens?: number }
  }

  const content = payload.choices?.[0]?.message?.content
  if (!content) {
    throw new Error("OpenAI response missing content")
  }

  return {
    content,
    tokensUsed: payload.usage?.total_tokens ?? null,
  }
}

const callAnthropic = async (params: { apiKey: string; prompt: string; model: string }) => {
  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": params.apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: params.model,
      max_tokens: 1024,
      temperature: 0,
      system: "You are SecureAI, a precise application security analyst. Respond with JSON only.",
      messages: [
        {
          role: "user",
          content: [{ type: "text", text: params.prompt }],
        },
      ],
    }),
  })

  if (!response.ok) {
    const detail = await response.text().catch(() => "")
    throw new Error(`Anthropic request failed: ${response.status} ${detail}`)
  }

  const payload = (await response.json()) as {
    content?: Array<{ text?: string }>
    usage?: { total_tokens?: number; input_tokens?: number; output_tokens?: number }
  }

  const text = payload.content?.[0]?.text
  if (!text) {
    throw new Error("Anthropic response missing content")
  }

  const aggregatedTokens =
    payload.usage?.total_tokens ??
    (payload.usage?.input_tokens ?? 0) + (payload.usage?.output_tokens ?? 0)
  const tokens = typeof aggregatedTokens === "number" && Number.isFinite(aggregatedTokens) ? aggregatedTokens : null

  return {
    content: text,
    tokensUsed: tokens,
  }
}

const callGemini = async (params: { apiKey: string; prompt: string; model: string }) => {
  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${params.model}:generateContent?key=${params.apiKey}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        contents: [
          {
            role: "user",
            parts: [{ text: params.prompt }],
          },
        ],
        generationConfig: {
          temperature: 0.1,
          responseMimeType: "application/json",
        },
      }),
    },
  )

  if (!response.ok) {
    const detail = await response.text().catch(() => "")
    throw new Error(`Gemini request failed: ${response.status} ${detail}`)
  }

  const payload = (await response.json()) as {
    candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>
    usageMetadata?: { totalTokenCount?: number }
  }

  const text = payload.candidates?.[0]?.content?.parts?.[0]?.text
  if (!text) {
    throw new Error("Gemini response missing content")
  }

  return {
    content: text,
    tokensUsed: payload.usageMetadata?.totalTokenCount ?? null,
  }
}

const analyzeWithProvider = async (provider: Provider, apiKey: string, prompt: string) => {
  const model = DEFAULT_MODELS[provider]
  switch (provider) {
    case "openai":
      return callOpenAI({ apiKey, prompt, model })
    case "anthropic":
      return callAnthropic({ apiKey, prompt, model })
    case "gemini":
      return callGemini({ apiKey, prompt, model })
    default:
      throw new Error(`Unsupported provider: ${provider}`)
  }
}

const buildSummary = (raw: RawAiResponse): string => {
  return (
    ensureString(raw.summary) ??
    ensureString(raw.overview) ??
    ensureString(raw.riskSummary) ??
    "AI review completed. See detailed findings below."
  )
}

export async function POST(req: Request) {
  const body = (await req.json().catch(() => null)) as AnalysisRequestBody | null
  if (!body) {
    return NextResponse.json({ error: "INVALID_REQUEST", message: "Invalid JSON payload." }, { status: 400 })
  }

  const apiKey = ensureString(body.apiKey)
  const provider = body.provider?.toLowerCase() as Provider
  const code = ensureString(body.code)
  const fileName = ensureString(body.fileName) ?? "uploaded-file"
  const mode: AnalysisMode = body.mode === "dependencies" ? "dependencies" : "code"

  if (!apiKey) {
    return NextResponse.json({ error: "MISSING_API_KEY", message: "Provide a decrypted API key." }, { status: 400 })
  }

  if (!provider || !SUPPORTED_PROVIDERS.includes(provider)) {
    return NextResponse.json(
      {
        error: "UNSUPPORTED_PROVIDER",
        message: `Supported providers are: ${SUPPORTED_PROVIDERS.join(", ")}.`,
      },
      { status: 400 },
    )
  }

  if (!code) {
    return NextResponse.json({ error: "EMPTY_CODE", message: "Upload code to analyze." }, { status: 400 })
  }

  try {
  const prompt = buildPrompt(fileName, body.code, body.confidence, mode)
  const { content, tokensUsed } = await analyzeWithProvider(provider, apiKey, prompt)
  const raw = extractJsonObject(content)
  const summary = buildSummary(raw)
  const vulnerabilities = normalizeVulnerabilities(raw, fileName)

    return NextResponse.json({
      summary,
      provider,
      tokensUsed: tokensUsed ?? null,
      vulnerabilities,
    })
  } catch (error) {
    console.error("AI analysis failed", error)
    return NextResponse.json(
      {
        error: "AI_ANALYSIS_FAILED",
        message: "We could not complete the AI assessment. Verify your API key, provider choice, and usage limits.",
      },
      { status: 502 },
    )
  }
}
