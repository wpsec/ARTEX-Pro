export const AUTH_TOKEN_KEY = "artex_token";

const COOKIE_MAX_AGE = 7 * 24 * 60 * 60;

function normalizedPort(port: string): number | null {
  if (!/^\d{1,5}$/.test(port)) return null;
  const value = Number(port);
  return Number.isInteger(value) && value >= 1 && value <= 65535 ? value : null;
}

export function authCookieName(port: string): string {
  const value = normalizedPort(port);
  if (value === null || value === 80 || value === 443) return AUTH_TOKEN_KEY;
  return `${AUTH_TOKEN_KEY}_p${value}`;
}

export function authCookieMatchesToken(token: string, port: string): boolean {
  if (typeof document === "undefined") return false;
  const prefix = `${authCookieName(port)}=`;
  const cookie = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix));
  if (!cookie) return false;
  const value = cookie.slice(prefix.length);
  try {
    return decodeURIComponent(value) === token;
  } catch {
    return false;
  }
}

export function syncAuthCookie(token: string, port: string): void {
  if (typeof document === "undefined" || authCookieMatchesToken(token, port)) return;
  // biome-ignore lint/suspicious/noDocumentCookie: Next.js proxy and the Go API both authenticate from this cookie.
  document.cookie = `${authCookieName(port)}=${encodeURIComponent(token)}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax`;
}

export function clearAuthCookie(port: string): void {
  if (typeof document === "undefined") return;
  // biome-ignore lint/suspicious/noDocumentCookie: Remove the current instance cookie after logout or token rejection.
  document.cookie = `${authCookieName(port)}=; path=/; max-age=0; SameSite=Lax`;
}
