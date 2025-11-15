# OneStop-CYworld AI Coding Agent Instructions

## Project Identity
**Brand**: OneStop-CYworld (rebranded from "SecureAI")  
**Mission**: Cybersecurity workspace combining static analysis, AI-powered code review, dependency scanning, password breach lookup, and threat intelligence feeds

## Tech Stack Core
- **Framework**: Next.js 15.5.4 (App Router) + React 19.1.0 + TypeScript (strict mode)
- **Styling**: Tailwind CSS v4 with terminal-inspired aesthetic; orange brand accent (`#ff8c00` / `text-brand`)
- **UI Components**: Radix UI primitives + Framer Motion animations + Lucide icons
- **State**: Zustand 5.0.8 (flat state structure: `currentScan`, `aiConfig`, `theme`, `sidebarOpen`)
- **API Runtime**: Edge functions preferred for lightweight operations; Node.js runtime for file system access

## Architecture Patterns

### 1. Terminal-Inspired UI System
**Component**: `components/layout/terminal-box.tsx`  
**Pattern**: All feature pages wrap content in `<TerminalBox title="...">` for consistent borders and styling
```tsx
<TerminalBox title="Security Scan">
  {/* content with terminal aesthetic */}
</TerminalBox>
```
- Orange accent borders (`border-brand`)
- Monospace fonts for code display
- Consistent padding and shadow styles

### 2. Multi-Provider AI Abstraction
**Endpoint**: `app/api/ai/analyze/route.ts`  
**Pattern**: Provider-agnostic interface with normalized responses
```ts
// Provider detection
const provider = aiConfig.provider || "openai"

// Provider-specific calls
if (provider === "openai") callOpenAI(...)
else if (provider === "anthropic") callAnthropic(...)
else if (provider === "gemini") callGemini(...)

// Normalized response shape
{ summary, vulnerabilities: [{ id, title, severity, rule, line, ... }] }
```
- Always map findings to CWE identifiers (`rule` property)
- Severity normalization: `critical | high | medium | low`
- JSON extraction from AI responses with fallback parsing

### 3. Client-Side Encryption Pattern
**Context**: API keys stored encrypted in localStorage, never sent unencrypted
**Implementation**:
```ts
// Encryption: AES-GCM with salt/IV stored separately
const encryptApiKey = async (apiKey: string, passphrase: string) => {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveEncryptionKey(passphrase, salt)
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(apiKey))
  return { salt: base64(salt), iv: base64(iv), cipher: base64(cipher) }
}

// Decryption: Reconstruct key from passphrase + salt
const decryptApiKey = async (config: StoredConfig, passphrase: string) => {
  const cryptoKey = await deriveEncryptionKey(passphrase, base64ToUint8Array(config.salt))
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBuffer }, cryptoKey, cipherBuffer)
  return bufferToString(decrypted)
}
```
**Usage**: All AI and external API integrations use this pattern (see `app/ai-assess/page.tsx`, `app/dependency-scanner/page.tsx`)

### 4. Heuristic Vulnerability Detection
**Location**: `app/scan/page.tsx` - `detectors` array  
**Pattern**: Array of rule objects with `test` functions
```ts
interface Detector {
  id: string
  type: string           // "SQL Injection", "XSS", etc.
  severity: Severity     // "critical" | "high" | "medium" | "low"
  rule: string           // CWE identifier (e.g., "CWE-89")
  message: string
  remediation: string
  appliesTo?: Language[] // ["javascript", "python", etc.]
  test: (ctx: DetectorContext) => boolean
}
```
**Critical Rules**:
- `CWE-94`: Dynamic code execution (`eval`)
- `CWE-78`: OS command injection (`exec`, `system`)
- `CWE-89`: SQL injection (string concatenation patterns)
- `CWE-79`: DOM XSS (`innerHTML`, template literals)
- `CWE-918`: SSRF (user input to `fetch`, `axios`, etc.)

### 5. RSS News Aggregation
**Library**: `lib/news.ts` - `fetchSecurityNews(limit: number)`  
**Pattern**: RSS2JSON proxy → deduplication → date grouping
```ts
// Fetch from multiple sources
const feeds = [
  "https://thehackernews.com/feeds/posts/default",
  "https://bleepingcomputer.com/feed/",
  "https://cisa.gov/cybersecurity-advisories/...rss.xml"
]

// Normalize and deduplicate
const items = feeds.flatMap(feedUrl => {
  const data = await fetch(`https://api.rss2json.com/v1/api.json?rss_url=${feedUrl}`)
  return data.items.map(normalizeNewsItem)
}).filter(deduplicateByTitle)

// Client polls every 30 minutes
useEffect(() => {
  fetchNews()
  const interval = setInterval(fetchNews, 30 * 60 * 1000)
  return () => clearInterval(interval)
}, [])
```

### 6. Dependency Scanning Workflow
**Endpoint**: `app/api/dependency-scan/route.ts` → OSV.dev API  
**Flow**:
1. Parse manifest (requirements.txt, package.json, go.mod) using `detectManifestType()`
2. Query OSV.dev for each package
3. Group vulnerabilities by dependency with severity + fixed version
4. Optional: Send to AI for remediation plan generation

## Naming Conventions
- **Brand References**: Always "OneStop-CYworld" (never "SecureAI")
- **Theme Storage**: `localStorage.getItem("onestopcyworld-theme")`
- **Colors**: Orange primary (`#ff8c00`), terminal green accents for success states
- **Severity Styling**:
  - Critical: `text-red-500`, `border-red-500/30`
  - High: `text-orange-500`, `border-orange-500/30`
  - Medium: `text-amber-500`, `border-amber-500/30`
  - Low: `text-blue-500`, `border-blue-500/30`

## Feature Status
- ✅ **Active**: Basic Scan, AI-Assisted Review, Dependency Scanner, Password Breach Lookup, Security News Feed, Theme Toggle
- ❌ **Deprecated**: Games section (routes return 404, APIs return 410 Gone, state removed from Zustand store)

## Critical Constraints
1. **Type Safety**: React 19 types required (`@types/react@^19`, `@types/react-dom@^19`)
2. **No Server State**: Use Zustand for client state; avoid Redux/Context
3. **Edge Runtime First**: Prefer `export const runtime = "edge"` for API routes unless filesystem access needed
4. **Security Focus**: All user input must be validated; highlight CWE mappings in vulnerability reports
5. **Responsive Design**: Mobile-first with `lg:` breakpoints for desktop layouts

## Integration Points
- **AI Providers**: OpenAI (`gpt-4o-mini`), Anthropic (`claude-3-5-sonnet-20241022`), Gemini (`gemini-2.0-flash-exp`)
- **Security APIs**: OSV.dev (CVE lookup), Have I Been Pwned (k-anonymity password checks), RSS2JSON (news proxy)
- **Analytics**: Vercel Analytics enabled in root layout

## Development Commands
```bash
npm run dev      # Start dev server (port 3000)
npm run build    # Production build with type checking
npm run lint     # ESLint validation
```

## Code Style
- **Line Length**: Prefer 120-140 chars; break at logical boundaries
- **Async Patterns**: `async/await` over promises; handle errors with try/catch blocks
- **Component Structure**: Client components marked with `"use client"`; server components default
- **Import Order**: React → Next.js → third-party → local components → utilities → types

## When Making Changes
1. **Branding**: Use "OneStop-CYworld" consistently across UI text, metadata, and comments
2. **Detectors**: Add new vulnerability rules to `app/scan/page.tsx` `detectors` array with CWE mapping
3. **AI Prompts**: Update system prompts in `app/api/ai/analyze/route.ts` `buildPrompt()` function
4. **Navigation**: Header navigation in `components/layout/header.tsx` (current routes: `/scan`, `/ai-assess`, `/dependency-scanner`, `/pass-strength`, `/news`, `/config`, `/docs`)
5. **State Changes**: Update Zustand store in `stores/app-store.ts` and TypeScript interfaces in `types/index.ts`

## Common Gotchas
- **JSX Type Errors**: Ensure React 19 types match runtime version
- **Edge Runtime Limits**: No `fs`, `child_process`, or Node.js APIs in edge functions
- **localStorage Access**: Always check `typeof window !== "undefined"` before accessing
- **Theme Persistence**: Use `localStorage.setItem("onestopcyworld-theme", theme)` format
- **CWE Mapping**: Every vulnerability must have a `rule` property with CWE identifier

---
**Last Updated**: Post-rebrand, post-games-removal, security intelligence feed live
