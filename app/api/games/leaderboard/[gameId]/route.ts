import { NextResponse } from "next/server"

export async function GET(_: Request, ctx: { params: { gameId: string } }) {
  const { gameId } = ctx.params
  // TODO: query DB for leaderboard
  return NextResponse.json({
    gameId,
    leaderboard: [
      { rank: 1, username: "neo", score: 200, date: new Date().toISOString() },
      { rank: 2, username: "trinity", score: 150, date: new Date().toISOString() },
    ],
  })
}
