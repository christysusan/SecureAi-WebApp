import { NextResponse } from "next/server"

export async function POST(req: Request, ctx: { params: { gameId: string } }) {
  const { gameId } = ctx.params
  const body = await req.json().catch(() => null)
  if (!body || typeof body.score !== "number") {
    return NextResponse.json({ error: "Invalid payload" }, { status: 400 })
  }
  // TODO: persist score and return rank
  return NextResponse.json({ ok: true, gameId, score: body.score, rank: 1 })
}
