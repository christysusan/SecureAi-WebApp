import { cn } from "@/lib/utils"

export function ProgressBar({ value, className }: { value: number; className?: string }) {
  const clamped = Math.max(0, Math.min(100, value))
  return (
    <div
      className={cn("w-full h-2 rounded bg-surface border border-border overflow-hidden", className)}
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={clamped}
    >
      <div className="h-full bg-brand transition-all duration-300" style={{ width: `${clamped}%` }} />
    </div>
  )
}
