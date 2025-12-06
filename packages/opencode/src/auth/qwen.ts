import os from "os"
import path from "path"
import { Auth } from "./index"
import z from "zod/v4"
import { NamedError } from "@opencode-ai/util/error"

/**
 * Qwen OAuth Authentication Module
 *
 * This module implements OAuth Device Flow authentication for Qwen Coder.
 * Currently uses placeholder endpoints that need to be updated with the actual Qwen OAuth API endpoints.
 *
 * TODO: Find the correct Qwen OAuth endpoints:
 * - Device code endpoint (currently: https://chat.qwen.ai/oauth/device/code)
 * - Token endpoint (currently: https://chat.qwen.ai/oauth/token)
 *
 * The authorization URL format is known: https://chat.qwen.ai/authorize?user_code={code}&client=qwen-code
 *
 * Once the correct endpoints are found, update DEVICE_CODE_URL and ACCESS_TOKEN_URL constants.
 */

export namespace AuthQwen {
  const QWEN_OAUTH_FILE = path.join(os.homedir(), ".qwen", "oauth_creds.json")
  // TODO: Replace with actual Qwen OAuth device code endpoint
  const DEVICE_CODE_URL = "https://chat.qwen.ai/oauth/device/code"
  // TODO: Replace with actual Qwen OAuth token endpoint
  const ACCESS_TOKEN_URL = "https://chat.qwen.ai/oauth/token"
  export const AUTH_URL = "https://chat.qwen.ai/authorize"

  interface DeviceCodeResponse {
    device_code: string
    user_code: string
    verification_uri: string
    expires_in: number
    interval: number
  }

  interface AccessTokenResponse {
    access_token?: string
    refresh_token?: string
    expires_in?: number
    error?: string
    error_description?: string
  }

  interface QwenOAuthCreds {
    access_token: string
    refresh_token?: string
    expires_at?: number
    expiry_date?: number // Qwen CLI stores expiry in milliseconds
    resource_url?: string
  }

  async function readExternalCreds(): Promise<QwenOAuthCreds | undefined> {
    try {
      const file = Bun.file(QWEN_OAUTH_FILE)
      const creds = await file.json()
      // Map Qwen CLI format to our internal format
      return {
        access_token: creds.access_token,
        refresh_token: creds.refresh_token,
        expires_at: creds.expiry_date || creds.expires_at, // Qwen CLI uses expiry_date in milliseconds
        resource_url: creds.resource_url,
      }
    } catch {
      return undefined
    }
  }

  function isExpired(expiresAt?: number): boolean {
    if (!expiresAt) return true
    return expiresAt < Date.now() // expiresAt is now in milliseconds
  }

  async function refreshToken(refreshToken: string): Promise<QwenOAuthCreds | undefined> {
    try {
      const response = await fetch(ACCESS_TOKEN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: "qwen-code",
        }),
      })

      if (!response.ok) return undefined
      const data = await response.json()
      // Convert expires_in (seconds) to expires_at (milliseconds)
      return {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_at: data.expires_in ? Date.now() + data.expires_in * 1000 : undefined,
        resource_url: data.resource_url,
      }
    } catch {
      // If refresh fails (e.g., invalid endpoints), return undefined
      return undefined
    }
  }

  export async function authorize() {
    // TODO: Replace with actual Qwen OAuth device code endpoint
    // Based on research, this should be something like:
    // https://chat.qwen.ai/api/oauth/device/code or similar
    const deviceResponse = await fetch(DEVICE_CODE_URL, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "User-Agent": "QwenCode/1.0.0",
      },
      body: JSON.stringify({
        client_id: "qwen-code",
        scope: "read:user",
      }),
    })

    if (!deviceResponse.ok) {
      throw new Error(`Failed to get device code: ${deviceResponse.status} ${deviceResponse.statusText}`)
    }

    const deviceData: DeviceCodeResponse = await deviceResponse.json()
    return {
      device: deviceData.device_code,
      user: deviceData.user_code,
      verification: deviceData.verification_uri,
      interval: deviceData.interval || 5,
      expiry: deviceData.expires_in,
    }
  }

  export async function poll(device_code: string) {
    // TODO: Replace with actual Qwen OAuth token endpoint
    // Based on research, this should be something like:
    // https://chat.qwen.ai/api/oauth/token or similar
    const response = await fetch(ACCESS_TOKEN_URL, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "User-Agent": "QwenCode/1.0.0",
      },
      body: JSON.stringify({
        client_id: "qwen-code",
        device_code,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      }),
    })

    if (!response.ok) {
      // If we get a server error, consider it failed
      if (response.status >= 500) return "failed"
      throw new Error(`Token request failed: ${response.status} ${response.statusText}`)
    }

    const data: AccessTokenResponse = await response.json()

    if (data.access_token) {
      // Store the Qwen OAuth token
      await Auth.set("qwen", {
        type: "oauth",
        refresh: data.refresh_token || "",
        access: data.access_token,
        expires: data.expires_in ? Date.now() + data.expires_in * 1000 : 0,
      })
      return "complete"
    }

    if (data.error === "authorization_pending") return "pending"

    if (data.error === "slow_down") {
      // Client should slow down polling
      return "pending"
    }

    if (data.error === "expired_token") return "failed"

    if (data.error) return "failed"

    return "pending"
  }

  export async function access(): Promise<string | undefined> {
    const info = await Auth.get("qwen")
    if (info?.type === "oauth") {
      if (info.access && info.expires > Date.now()) {
        return info.access
      }

      if (info.refresh) {
        const newCreds = await refreshToken(info.refresh)
        if (newCreds) {
          await Auth.set("qwen", {
            type: "oauth",
            refresh: newCreds.refresh_token || info.refresh,
            access: newCreds.access_token,
            expires: newCreds.expires_at ? newCreds.expires_at : 0,
          })
          return newCreds.access_token
        }
      }
    }

    const externalCreds = await readExternalCreds()
    if (externalCreds) {
      if (!isExpired(externalCreds.expires_at)) {
        return externalCreds.access_token
      }

      if (externalCreds.refresh_token) {
        const newCreds = await refreshToken(externalCreds.refresh_token)
        if (newCreds) {
          await Auth.set("qwen", {
            type: "oauth",
            refresh: newCreds.refresh_token || externalCreds.refresh_token,
            access: newCreds.access_token,
            expires: newCreds.expires_at ? newCreds.expires_at : 0,
          })
          return newCreds.access_token
        }
      }
    }

    return undefined
  }

  export const DeviceCodeError = NamedError.create("DeviceCodeError", z.object({}))

  export const TokenExchangeError = NamedError.create(
    "TokenExchangeError",
    z.object({
      message: z.string(),
    }),
  )

  export const AuthenticationError = NamedError.create(
    "AuthenticationError",
    z.object({
      message: z.string(),
    }),
  )
}
