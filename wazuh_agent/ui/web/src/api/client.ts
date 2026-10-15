import type { ConnectionResult, Status, UpdateInfo } from './types'

export class ApiError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

/**
 * Builds the URL of an API call relative to the page. Home Assistant serves the page under an
 * ingress path it chooses (/api/hassio_ingress/<token>/), so absolute URLs would miss it.
 */
export function apiUrl(path: string, location: Pick<Location, 'href'> = window.location): string {
  const page = new URL(location.href)
  page.search = ''
  page.hash = ''
  if (!page.pathname.endsWith('/')) page.pathname += '/'
  return new URL(`api/${path}`, page).toString()
}

export async function getJson<T>(path: string, fetcher: typeof fetch = fetch): Promise<T> {
  const response = await fetcher(apiUrl(path), {
    headers: { Accept: 'application/json' },
    cache: 'no-store',
  })
  if (!response.ok)
    throw new ApiError(`The status service answered ${response.status}`, response.status)
  return (await response.json()) as T
}

export const api = {
  status: (): Promise<Status> => getJson<Status>('status'),
  updates: (refresh = false): Promise<UpdateInfo> =>
    getJson<UpdateInfo>(refresh ? 'updates?refresh=1' : 'updates'),
  logs: async (): Promise<string[]> => (await getJson<{ lines: string[] }>('logs')).lines,
  connectionTest: async (): Promise<ConnectionResult[]> =>
    (await getJson<{ results: ConnectionResult[] }>('connection-test')).results,
}
