import client from './client'
import type { CatalogItem } from '@/types'

export const listCatalog = (params?: { search?: string; category?: string; page_size?: number }) => {
  const query = new URLSearchParams()
  if (params?.search) query.set('search', params.search)
  if (params?.category) query.set('category', params.category)
  query.set('page_size', String(params?.page_size ?? 100))
  return client.get<CatalogItem[]>(`/catalog?${query}`).then(r => r.data)
}

export const getCatalogItem = (id: string) =>
  client.get<CatalogItem>(`/catalog/${id}`).then(r => r.data)

export const createCatalogItem = (body: Partial<CatalogItem> & { catalog_item_id: string; canonical_name: string; category: string }) =>
  client.post<CatalogItem>('/catalog', body).then(r => r.data)

export const updateCatalogItem = (id: string, body: Partial<CatalogItem>) =>
  client.put<CatalogItem>(`/catalog/${id}`, body).then(r => r.data)

export const deleteCatalogItem = (id: string) =>
  client.delete(`/catalog/${id}`).then(r => r.data)
