import { useI18n } from '@/i18n'
import { Globe, Puzzle, Key, Cpu, Container, Monitor, Code } from 'lucide-react'


const ICON_MAP: Record<string, React.ElementType> = {
  saas_app: Globe,
  api_service: Code,
  browser_extension: Puzzle,
  oauth_app: Key,
  local_runtime: Cpu,
  local_container: Container,
  desktop_app: Monitor,
}

const LABEL_MAP: Record<string, string> = {
  saas_app: 'SaaS',
  api_service: 'API',
  browser_extension: 'Extension',
  oauth_app: 'OAuth',
  local_runtime: 'Local',
  local_container: 'Container',
  desktop_app: 'Desktop',
}

interface Props {
  entityType: string
  showLabel?: boolean
}

export default function EntityTypeBadge({ entityType, showLabel = true }: Props) {
  const { textLabel } = useI18n()

  const Icon = ICON_MAP[entityType] || Globe
  const label = LABEL_MAP[entityType] || entityType.replace('_', ' ')

  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-surface-700 text-slate-300 text-xs">
      <Icon className="w-3 h-3" />
      {showLabel && textLabel(label)}
    </span>
  )
}
