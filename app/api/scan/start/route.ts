import { NextResponse } from "next/server"

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({} as { target?: string }))
  const id = Math.random().toString(36).slice(2, 10)
  // TODO: enqueue scan job, validate target/options, apply rate limiting
  const target = typeof body.target === "string" && body.target.trim() ? body.target.trim() : "unspecified"
  return NextResponse.json({ id, status: "queued", target })
}
