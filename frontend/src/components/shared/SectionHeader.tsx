"use client";

export default function SectionHeader({
  eyebrow,
  title,
  description,
  right
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  right?: React.ReactNode;
}) {
  return (
    <div className="flex items-end justify-between gap-4 mb-4">
      <div>
        {eyebrow && (
          <div className="text-[11px] uppercase tracking-[0.2em] text-accent mb-1">{eyebrow}</div>
        )}
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-sm text-muted max-w-2xl mt-1">{description}</p>}
      </div>
      {right}
    </div>
  );
}
