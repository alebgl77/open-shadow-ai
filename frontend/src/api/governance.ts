import client from './client'
import type { Governance } from '@/types'

export const listGovernance = (targetType?: string) => {
  const params = targetType ? `?target_type=${targetType}` : ''
  return client.get<Governance[]>(`/governance${params}`).then(r => r.data)
}

export const createGovernance = (body: {
  target_type: string
  target_id: string
  org_classification: string
  owner?: string
  justification?: string
  enforcement_mode?: string
}) => client.post<Governance>('/governance', body).then(r => r.data)

export const updateGovernance = (id: string, body: Partial<Governance>) =>
  client.put<Governance>(`/governance/${id}`, body).then(r => r.data)
