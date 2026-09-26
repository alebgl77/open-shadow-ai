import { QueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'

export const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 30_000, retry: 2, refetchOnWindowFocus: false } },
})
// Every sign-in method and sign-out crosses the same cache/session boundary.
useAuthStore.subscribe((state, previous) => {
  if (state.session !== previous.session) queryClient.clear()
})
