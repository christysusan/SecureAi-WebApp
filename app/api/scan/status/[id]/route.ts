import { NextResponse } from "next/server"

export async function GET(_: Request, ctx: { params: { id: string } }) {
  const { id } = ctx.params
  // TODO: fetch real progress/results from store or DB
  return NextResponse.json({
    id,
    status: "running",
    progress: 42,
    results: [],
  })
}
