import { NextResponse } from "next/server"

const retiredResponse = NextResponse.json(
  {
    error: "GAMES_RETIRED",
    message: "Security arcade endpoints are no longer available.",
  },
  { status: 410 },
)

export async function POST() {
  return retiredResponse
}
