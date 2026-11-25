import { AUTH_TOKEN_KEY, clearAuthCookie, syncAuthCookie } from "./auth-cookie";

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const auth = {
  getToken(): string | null {
    if (typeof window === "undefined") return null;
    // Mock demo：无真实登录，返回一个假 token 让路由守卫放行、直接进主界面。
    const token = localStorage.getItem(AUTH_TOKEN_KEY);
    if (token) syncAuthCookie(token, window.location.port);
    return token ?? (process.env.NEXT_PUBLIC_MOCK === "1" ? "mock-demo" : null);
  },

  setToken(token: string): void {
    localStorage.setItem(AUTH_TOKEN_KEY, token);
    syncAuthCookie(token, window.location.port);
  },

  clearToken(): void {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    clearAuthCookie(window.location.port);
  },

  // 从 JWT payload 的 sub 字段解析当前用户，仅用于展示，不做签名验证。
  getCurrentUser(): CurrentUser | null {
    const token = this.getToken();
    if (!token) return null;
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      // base64url → base64
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      const username: string = payload.sub ?? "ARTEX";
      return { id: "1", name: username, username, email: "", avatar: "", role: "operator" };
    } catch {
      return null;
    }
  },
};
