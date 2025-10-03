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
        "rounded-md border border-border bg-surface shadow-[0_0_0_1px_rgba(255,140,0,0.05)_inset] overflow-hidden",
        className,
      )}
      aria-label={title}
    >
      {title ? (
        <div className="px-3 py-2 font-mono text-xs text-foreground/80 bg-surface/80 border-b border-border">
          <span className="text-brand">{"┌ "}</span>
          <span>{title}</span>
          <span className="text-brand">{" ┐"}</span>
        </div>
      ) : null}
      <div className="p-4">{children}</div>
    </section>
  )
}
