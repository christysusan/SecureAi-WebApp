import type { ReactNode } from "react"
import { cn } from "@/lib/utils"

export function TerminalBox({
  title,
  children,
  className,
}: {
  title?: string
  children: ReactNode
  className?: string
}) {
  return (
    <section
      className={cn(
        "rounded-lg border border-[#E8E2D0] bg-surface shadow-sm overflow-hidden",
        className,
      )}
      aria-label={title}
    >
      {title ? (
        <div className="px-4 py-3 font-mono text-sm text-[#355952]/70 bg-[#F5F1E4] border-b border-[#E8E2D0]">
          <span className="text-[#355952] font-medium">{"┌ "}</span>
          <span>{title}</span>
          <span className="text-[#355952] font-medium">{" ┐"}</span>
        </div>
      ) : null}
      <div className="p-6">{children}</div>
    </section>
  )
}
