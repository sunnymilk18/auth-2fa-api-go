const API_URL = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '')
const API_KEY = import.meta.env.VITE_API_KEY

async function request(path, options = {}) {
  if (!API_URL) {
    throw new Error('Falta configurar VITE_API_URL en el frontend.')
  }

  if (!API_KEY && options.requiresApiKey !== false) {
    throw new Error('Falta configurar VITE_API_KEY en el frontend.')
  }

  const { body, accessToken, requiresApiKey = true, ...fetchOptions } = options
  const headers = new Headers(fetchOptions.headers)

  if (body !== undefined) {
    headers.set('Content-Type', 'application/json')
    fetchOptions.body = JSON.stringify(body)
  }

  if (requiresApiKey && API_KEY) {
    headers.set('X-API-Key', API_KEY)
  }

  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`)
  }

  let response
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...fetchOptions,
      headers,
    })
  } catch {
    throw new Error('No se pudo conectar con la API. Comprueba la URL, CORS y que el servicio esté disponible.')
  }

  const contentType = response.headers.get('content-type') || ''
  const data = contentType.includes('application/json')
    ? await response.json()
    : await response.text()

  if (!response.ok) {
    const message = typeof data === 'object' && data?.error
      ? data.error
      : `API request failed with status ${response.status}`
    const error = new Error(message)
    error.status = response.status
    error.data = data
    throw error
  }

  return data
}

export const api = {
  health: () => request('/health', { requiresApiKey: false }),

  register: (email, password) => request('/auth/register', {
    method: 'POST',
    body: { email, password },
  }),

  login: (email, password) => request('/auth/login', {
    method: 'POST',
    body: { email, password },
  }),

  verifyOtp: (loginToken, code) => request('/auth/verify-otp', {
    method: 'POST',
    body: { login_token: loginToken, code },
  }),

  confirmEmail: (email, code) => request('/auth/verify-email/confirm', {
    method: 'POST',
    body: { email, code },
  }),

  requestPasswordReset: (email) => request('/auth/password-reset/request', {
    method: 'POST',
    body: { email },
  }),

  confirmPasswordReset: (email, code, newPassword) => request('/auth/password-reset/confirm', {
    method: 'POST',
    body: { email, code, new_password: newPassword },
  }),

  refresh: (refreshToken) => request('/auth/refresh', {
    method: 'POST',
    body: { refresh_token: refreshToken },
  }),

  logout: (refreshToken, accessToken) => request('/auth/logout', {
    method: 'POST',
    body: { refresh_token: refreshToken },
    accessToken,
  }),

  me: (accessToken) => request('/me', {
    method: 'GET',
    accessToken,
  }),
}

export { request }
