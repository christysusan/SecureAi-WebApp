"use client"

export function BackgroundOrnaments() {
  return (
    <div aria-hidden="true" className="pointer-events-none absolute inset-x-0 bottom-0 -z-10" style={{ height: "50%" }}>
      {/* container for ornaments */}
      <div className="relative mx-auto h-full w-full max-w-6xl opacity-25">
        {/* rotated squares */}
        <div className="absolute left-2 top-6 hidden h-6 w-6 -rotate-12 border border-brand/50 md:block" />
        <div className="absolute left-24 top-20 hidden h-4 w-4 rotate-45 border border-brand/40 md:block" />
        <div className="absolute left-40 bottom-16 hidden h-8 w-8 rotate-12 border border-brand/30 md:block" />
        <div className="absolute right-10 top-8 hidden h-5 w-5 -rotate-6 border border-brand/40 md:block" />
        <div className="absolute right-40 bottom-8 hidden h-7 w-7 rotate-45 border border-brand/30 md:block" />

        {/* cross marks */}
        <span className="absolute left-10 bottom-10 hidden md:block">
          <i className="block h-px w-6 bg-brand/40" />
          <i className="block h-6 w-px translate-x-3 bg-brand/40" />
        </span>
        <span className="absolute left-56 bottom-28 hidden md:block">
          <i className="block h-px w-5 bg-brand/30" />
          <i className="block h-5 w-px translate-x-[10px] bg-brand/30" />
        </span>
        <span className="absolute right-24 bottom-24 hidden md:block">
          <i className="block h-px w-8 bg-brand/30" />
          <i className="block h-8 w-px translate-x-4 bg-brand/30" />
        </span>

        {/* dotted “scan line” */}
        <div className="absolute inset-x-4 bottom-0 hidden border-t border-dashed border-brand/30 md:block" />
        <div className="absolute inset-y-6 right-8 hidden border-l border-dashed border-brand/20 md:block" />

        {/* subtle block grid (non-gradient) */}
        <div className="absolute inset-x-4 bottom-10 grid grid-cols-12 gap-2">
          {Array.from({ length: 12 }).map((_, i) => (
            <div key={i} className="hidden h-6 border border-border/40 bg-surface/50 md:block" />
          ))}
        </div>
      </div>
    </div>
  )
}
