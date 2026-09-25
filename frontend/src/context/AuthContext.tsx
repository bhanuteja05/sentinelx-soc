import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import {
  type AuthUser,
  type LoginCredentials,
  fetchMe,
  login as apiLogin,
  logout as apiLogout,
  getStoredToken,
  setStoredToken,
  removeStoredToken,
} from '../api/client'

export interface AuthContextType {
  user: AuthUser | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (credentials: LoginCredentials) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [token, setToken] = useState<string | null>(getStoredToken)
  const [isLoading, setIsLoading] = useState<boolean>(true)

  useEffect(() => {
    let mounted = true

    async function restoreSession() {
      const stored = getStoredToken()
      if (!stored) {
        if (mounted) {
          setUser(null)
          setToken(null)
          setIsLoading(false)
        }
        return
      }

      try {
        const me = await fetchMe()
        if (mounted) {
          setUser(me)
          setToken(stored)
        }
      } catch {
        if (mounted) {
          removeStoredToken()
          setUser(null)
          setToken(null)
        }
      } finally {
        if (mounted) {
          setIsLoading(false)
        }
      }
    }

    restoreSession()

    const handleUnauthorized = () => {
      removeStoredToken()
      setUser(null)
      setToken(null)
    }

    window.addEventListener('auth:unauthorized', handleUnauthorized)

    return () => {
      mounted = false
      window.removeEventListener('auth:unauthorized', handleUnauthorized)
    }
  }, [])

  const login = useCallback(async (credentials: LoginCredentials) => {
    const res = await apiLogin(credentials)
    setStoredToken(res.access_token)
    setToken(res.access_token)
    setUser(res.user)
  }, [])

  const logout = useCallback(async () => {
    try {
      await apiLogout()
    } finally {
      removeStoredToken()
      setToken(null)
      setUser(null)
    }
  }, [])

  const value = {
    user,
    token,
    isAuthenticated: !!user && !!token,
    isLoading,
    login,
    logout,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return ctx
}
