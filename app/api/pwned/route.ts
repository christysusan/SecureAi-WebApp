import { NextResponse } from "next/server"

export const runtime = "nodejs"

const HIBP_ENDPOINT = "https://api.pwnedpasswords.com/range/"

const isValidPrefix = (value: string): boolean => /^[0-9A-F]{5}$/i.test(value)

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url)
  const prefixParam = searchParams.get("prefix")?.trim().toUpperCase()

  if (!prefixParam || !isValidPrefix(prefixParam) || prefixParam.length !== 5) {
    return NextResponse.json(
      { error: "INVALID_PREFIX", message: "Query parameter 'prefix' must be a 5-character hex string." },
      { status: 400 },
    )
  }

  try {
    const response = await fetch(`${HIBP_ENDPOINT}${prefixParam}`, {
      method: "GET",
      headers: {
  "User-Agent": "OneStop-CYworld/1.0 (+https://github.com/Yampss/CHRISTY-PROJECT)",
        "Add-Padding": "true",
      },
      cache: "no-store",
    })

    if (!response.ok) {
      const detail = await response.text().catch(() => "")
      return NextResponse.json(
        { error: "HIBP_ERROR", message: `HIBP request failed: ${response.status}`, detail },
        { status: 502 },
      )
    }

    const matches = await response.text()

    return NextResponse.json({ prefix: prefixParam, matches })
  } catch (error) {
    return NextResponse.json(
      {
        error: "HIBP_REQUEST_FAILED",
        message: "Unable to reach the Have I Been Pwned range API.",
        detail: error instanceof Error ? error.message : String(error),
      },
      { status: 500 },
    )
  }
}
