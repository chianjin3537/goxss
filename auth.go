package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ══════════════ 管理后台认证 ══════════════
// 账号存储于 SQLite users 表（启动时若无 admin 账号则创建，初始密码 123456）
// bcrypt 哈希存储；会话为内存态 token

const (
	sessionCookie = "goxss_session"
	sessionTTL    = 24 * time.Hour
)

type Auth struct {
	mu       sync.Mutex
	sessions map[string]time.Time // token -> 过期时间
}

func newAuth() *Auth {
	a := &Auth{sessions: map[string]time.Time{}}
	go a.cleanup()
	return a
}

// Login 校验用户名密码（SQLite users 表），成功返回新会话 token
func (a *Auth) Login(user, pass string) (string, bool) {
	if !db.VerifyUser(user, pass) {
		return "", false
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", false
	}
	token := hex.EncodeToString(buf)
	a.mu.Lock()
	a.sessions[token] = time.Now().Add(sessionTTL)
	a.mu.Unlock()
	return token, true
}

// ChangePassword 修改密码：校验旧密码后更新，并可选择让该用户所有会话失效
func (a *Auth) ChangePassword(user, oldPass, newPass string) bool {
	if !db.VerifyUser(user, oldPass) {
		return false
	}
	if err := db.UpdatePassword(user, newPass); err != nil {
		log.Printf("[auth] 更新密码失败: %v", err)
		return false
	}
	// 密码变更后吊销全部会话，强制重新登录
	a.mu.Lock()
	a.sessions = map[string]time.Time{}
	a.mu.Unlock()
	log.Printf("[auth] 密码已修改 user=%s，所有会话已吊销", user)
	return true
}

// Valid 检查会话并滑动续期
func (a *Auth) Valid(token string) bool {
	if token == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[token]
	if !ok || time.Now().After(exp) {
		if ok {
			delete(a.sessions, token)
		}
		return false
	}
	a.sessions[token] = time.Now().Add(sessionTTL) // 滑动过期
	return true
}

func (a *Auth) Logout(token string) {
	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
}

// cleanup 每分钟清理过期会话
func (a *Auth) cleanup() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		a.mu.Lock()
		for t, exp := range a.sessions {
			if now.After(exp) {
				delete(a.sessions, t)
			}
		}
		a.mu.Unlock()
	}
}

// tokenFrom 优先 Cookie，其次 Authorization: Bearer（方便 API 调试）
func tokenFrom(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		return c.Value
	}
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// ══════════════ 后台入口令牌 ══════════════
// 随机路径不设常驻 Cookie 门禁：直接访问一律跳回首页。
// 只有 /h 会签发入口令牌（10 分钟有效、可复用，供登录页及其静态资源加载），
// 拼在随机 URL 的 ?e= 参数上；已登录会话也可直接访问。

const entryTTL = 10 * time.Minute

var entryMu sync.Mutex
var entryTokens = map[string]time.Time{} // token -> 过期时间

// IssueEntryToken 签发后台入口令牌
func IssueEntryToken() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	tok := hex.EncodeToString(buf)
	entryMu.Lock()
	entryTokens[tok] = time.Now().Add(entryTTL)
	// 顺手清理过期令牌
	now := time.Now()
	for t, exp := range entryTokens {
		if now.After(exp) {
			delete(entryTokens, t)
		}
	}
	entryMu.Unlock()
	return tok
}

// EntryValid 校验入口令牌
func EntryValid(tok string) bool {
	if tok == "" {
		return false
	}
	entryMu.Lock()
	defer entryMu.Unlock()
	exp, ok := entryTokens[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(entryTokens, tok)
		return false
	}
	return true
}

// entryTokenFrom 从 ?e= 查询参数或 X-Entry-Token 头读取
func entryTokenFrom(r *http.Request) string {
	if e := r.URL.Query().Get("e"); e != "" {
		return e
	}
	return r.Header.Get("X-Entry-Token")
}

// requireEntry 后台入口中间件：无有效入口令牌且未登录 → 重定向首页（伪装页）
func (a *Auth) requireEntry(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.Valid(tokenFrom(r)) && !EntryValid(entryTokenFrom(r)) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			} else {
				// 非 GET 直接 404，避免重定向语义混乱
				http.NotFound(w, r)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuth 鉴权中间件：未登录时页面跳 /login，API 返回 401
func (a *Auth) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.Valid(tokenFrom(r)) {
			if isAPIPath(r.URL.Path) {
				jsonWrite(w, http.StatusUnauthorized, map[string]string{"error": "未登录或会话已过期"})
			} else {
				// 保留部署随机路径前缀
				http.Redirect(w, r, basePath+"/login", http.StatusSeeOther)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isAPIPath(p string) bool {
	return strings.HasPrefix(p, "/api/") || p == "/ws"
}
