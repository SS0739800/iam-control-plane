/**
 * The handful of icons the console uses, drawn inline so there's no icon package
 * to pull in. All 16x16 on a 16-unit grid, stroked in currentColor so they take
 * the colour of whatever they sit in.
 */

type IconProps = { className?: string }

function Svg({ children, className }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      viewBox="0 0 16 16"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.3"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      {children}
    </svg>
  )
}

export function DashboardIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="2" y="2" width="5" height="5" rx="1" />
      <rect x="9" y="2" width="5" height="5" rx="1" />
      <rect x="2" y="9" width="5" height="5" rx="1" />
      <rect x="9" y="9" width="5" height="5" rx="1" />
    </Svg>
  )
}

export function UserIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="8" cy="5" r="2.6" />
      <path d="M2.8 13.4c.6-2.4 2.7-3.6 5.2-3.6s4.6 1.2 5.2 3.6" />
    </Svg>
  )
}

export function GroupIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="6" cy="5.4" r="2.2" />
      <circle cx="11.6" cy="6.2" r="1.7" />
      <path d="M1.8 13c.5-2 2.2-3.1 4.2-3.1s3.7 1.1 4.2 3.1" />
      <path d="M11.4 9.6c1.6.1 2.6 1 2.9 2.5" />
    </Svg>
  )
}

export function AppIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="2" y="3" width="12" height="10" rx="1.5" />
      <path d="M2 6h12" />
    </Svg>
  )
}

export function RuleIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3 4h10M3 8h10M3 12h6" />
    </Svg>
  )
}

export function RequestIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4 2.5h8a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1Z" />
      <path d="M5.8 8.2l1.4 1.4 3-3.2" />
    </Svg>
  )
}

export function ReviewIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="7.2" cy="7.2" r="4.2" />
      <path d="M10.4 10.4 13.6 13.6" />
    </Svg>
  )
}

export function ProvisionInIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M8 2.6v7.2" />
      <path d="M5.2 7l2.8 2.8L10.8 7" />
      <path d="M3 12.4h10" />
    </Svg>
  )
}

export function ProvisionOutIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M8 9.8V2.6" />
      <path d="M5.2 5.4 8 2.6l2.8 2.8" />
      <path d="M3 12.4h10" />
    </Svg>
  )
}

export function SignInIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M9.6 2.8h2.6a1 1 0 0 1 1 1v8.4a1 1 0 0 1-1 1H9.6" />
      <path d="M2.6 8h6.6" />
      <path d="M6.8 5.6 9.2 8l-2.4 2.4" />
    </Svg>
  )
}

export function AuditIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4 2.5h8a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1Z" />
      <path d="M5.6 6h4.8M5.6 8.6h4.8M5.6 11.2h2.8" />
    </Svg>
  )
}

export function RefreshIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M13.2 8a5.2 5.2 0 1 1-1.6-3.7" />
      <path d="M13.4 2.6v3.2h-3.2" />
    </Svg>
  )
}

export function FilterIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M2.6 3.4h10.8L9.4 8v4.2l-2.8 1.4V8L2.6 3.4Z" />
    </Svg>
  )
}

export function CloseIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4 4l8 8M12 4l-8 8" />
    </Svg>
  )
}
