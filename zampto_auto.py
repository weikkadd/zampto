#!/usr/bin/env python3
"""Zampto Auto Renewal v5 - Hybrid mode with Session Cookie Reuse.

Phase 1 (First run): 
  - Run locally with desktop GUI
  - Complete login manually in browser (solve Turnstile)
  - Script saves session cookies to ./screenshots/session.json

Phase 2 (GitHub Actions):
  - Encode session.json as base64 and store as SECRET (e.g., ZAMPTO_SESSION)
  - Decode at runtime, use requests.Session with saved cookies
  - Skip browser entirely, call /api/server/ status & renewal APIs directly

This bypasses Cloudflare Turnstile completely after the initial manual setup.
"""

import os, re, sys, json, time, logging, base64, tempfile
from datetime import datetime, timezone
try:
    import requests
except ImportError:
    print("requests not installed. Install: pip install requests")
    raise

# Try importing cloakbrowser only if needed
HAS_CLOAKBROWSER = False
try:
    from cloakbrowser import launch
    HAS_CLOAKBROWSER = True
except Exception:
    pass

USERNAME = os.getenv("ZAMPTO_USERNAME", "")
PASSWORD = os.getenv("ZAMPTO_PASSWORD", "")
SERVER_ID = os.getenv("ZAMPTO_SERVER_ID", "")
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")
FORCE_RENEW = os.getenv("FORCE_RENEW", "false").lower() == "true"
# 续期阈值 (小时): 剩余时间低于此值才续期, 与续期 API 判断保持一致
RENEW_THRESHOLD_HOURS = int(os.getenv("RENEW_THRESHOLD_HOURS", "48"))
DASHBOARD_URL = "https://dash.zampto.net"
SESSION_FILE = "./screenshots/session.json"
LOG_DIR = "./screenshots"

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("zampto")


def push_tg(title, body):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log.warning("Telegram config missing, skipping send")
        return
    try:
        # Pick up proxy from env (same as API session)
        proxy_url = os.getenv("ALL_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        r = requests.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT_ID, "text": f"{title}\n\n{body}", "parse_mode": "Markdown"},
            timeout=15,
            proxies=proxies,
        )
        r.raise_for_status()
        log.info("Telegram sent OK")
    except Exception as e:
        log.error("Telegram failed: %s", e)


def snap(page, name):
    os.makedirs(LOG_DIR, exist_ok=True)
    fp = os.path.join(LOG_DIR, name)
    page.screenshot(path=fp)
    log.info("Screenshot: %s", fp)
    return fp


def save_session_cookies(session_cookies, path=SESSION_FILE):
    """Save browser cookies to JSON file for reuse."""
    data = {"cookies": session_cookies, "saved_at": datetime.now(timezone.utc).isoformat()}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    log.info("Session saved to %s", path)


def load_session(path=SESSION_FILE):
    """Load saved session cookies from JSON file."""
    if not os.path.exists(path):
        log.info("No session file found - will need to log in via browser")
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cookies = data.get("cookies", [])
        log.info("Loaded %d saved cookies from session file", len(cookies))
        return cookies
    except Exception as e:
        log.error("Failed to load session: %s", e)
        return None


def sync_cookies_to_session(session_obj, cookies):
    """Sync a list of cookie dicts into a requests.Session.

    FIX: __Host- prefixed cookies (Laravel) require secure=True, path="/",
    and NO domain attribute. Python's cookielib rejects them if domain is
    non-empty, so we pass domain="" for __Host-/__Secure- cookies.
    """
    session_obj.cookies.clear()
    for c in cookies:
        name = c["name"]
        value = c["value"]
        try:
            if name.startswith("__Host-"):
                # __Host- 前缀: 必须 secure=True, path="/", 不能有 domain
                session_obj.cookies.set(
                    name, value,
                    path="/",
                    domain="",
                    secure=True,
                    expires=c.get("expires"),
                )
            elif name.startswith("__Secure-"):
                session_obj.cookies.set(
                    name, value,
                    domain=c.get("domain", ""),
                    path="/",
                    secure=True,
                    expires=c.get("expires"),
                )
            else:
                session_obj.cookies.set(
                    name, value,
                    domain=c.get("domain", ""),
                    path=c.get("path", "/"),
                    secure=c.get("secure", False),
                    expires=c.get("expires"),
                )
        except Exception as e:
            log.warning("Cookie set failed (%s): %s", name, e)
    log.info("Synced %d cookies to session", len(cookies))


def find_csrf_cookie(cookies):
    """Find the CSRF token from cookie list."""
    for c in cookies:
        name_lower = c.get("name", "").lower()
        if "csrf" in name_lower:
            return c["value"]
    return None


def refresh_csrf_token(api_session, base_url=DASHBOARD_URL, server_id=None):
    """Get a fresh CSRF token from server response.

    优先用 requests 内置的 r.cookies (RequestsCookieJar, 自动从 Set-Cookie 解析),
    再回退 Set-Cookie header 字符串解析 (兼容老代理), 最后回退 HTML <meta> / JS 提取。

    会尝试多种常见 CSRF cookie 名:
      zampto_csrf / XSRF-TOKEN / __Host-zampto_csrf / __Host-XSRF-TOKEN
      csrf_token / xsrf_token / laravel_csrf_token
    """
    CSRF_COOKIE_NAMES = [
        "zampto_csrf", "XSRF-TOKEN", "__Host-zampto_csrf", "__Host-XSRF-TOKEN",
        "csrf_token", "xsrf_token", "laravel_csrf_token",
    ]

    def extract_csrf(text):
        """从 HTML 中提取 CSRF token"""
        # <meta name="csrf-token" content="...">
        m = re.search(r'<meta\s+[^>]*name=[\'"]csrf-token[\'"]\s+content=[\'"]([^\'"]+)[\'"]', text, re.I)
        if m:
            return m.group(1)
        # var csrfToken = '...' 或 window.csrf = '...'
        m = re.search(r"(?:csrf|crsf|_token)\s*[:=]\s*[\"']([A-Za-z0-9_\-\.%]{40,300})", text, re.I)
        if m:
            return m.group(1)
        return None

    def apply_token(name, value):
        """把 token 写回 api_session.cookies 并返回"""
        # 不带 __Host- 前缀的 cookie, 用 .zampto.net 域; __Host- 前缀的不设 domain
        if name.startswith("__Host-"):
            api_session.cookies.set(name, value, path="/", domain="", secure=True)
        else:
            api_session.cookies.set(name, value, domain=".zampto.net", path="/")
        log.info("  ✓ CSRF from %s (len=%d)", name, len(value))
        return value

    try:
        for url in [f"{base_url}/", f"{base_url}/dashboard", f"{base_url}/api/servers"]:
            r = api_session.get(url, timeout=10)
            log.info("  CSRF refresh via %s (status=%d)", url, r.status_code)
            ct = (r.headers.get("content-type") or "").lower()

            # Method 1: requests 解析后的 r.cookies (最可靠)
            for cn in CSRF_COOKIE_NAMES:
                val = r.cookies.get(cn)
                if val:
                    return apply_token(cn, val)

            # Method 2: 从 Set-Cookie header 字符串解析 (兼容旧代理/特殊场景)
            set_cookies = []
            try:
                set_cookies = r.raw.headers.getlist("Set-Cookie")
            except (AttributeError, KeyError):
                if "Set-Cookie" in r.headers:
                    set_cookies.append(r.headers["Set-Cookie"])
            for sc in set_cookies:
                lower_sc = sc.lower()
                for cn in CSRF_COOKIE_NAMES:
                    cn_lower = cn.lower()
                    marker = cn_lower + "="
                    if marker in lower_sc:
                        start = lower_sc.index(marker) + len(marker)
                        rest = sc[start:]
                        end = rest.find(";")
                        token = rest[:end] if end != -1 else rest
                        token = token.strip()
                        if token:
                            return apply_token(cn, token)

            # Method 3: 从 HTML body 解析
            if "html" in ct:
                token = extract_csrf(r.text)
                if token:
                    log.info("  ✓ CSRF from HTML <meta>/JS (len=%d)", len(token))
                    api_session.cookies.set("zampto_csrf", token, domain=".zampto.net", path="/")
                    return token

        # Fallback: 已存在的 session.cookies (可能过期, 但值得一试)
        log.warning("  No fresh CSRF from Set-Cookie or HTML, using existing session.cookies")
        for c in api_session.cookies:
            cl = c.name.lower()
            if "csrf" in cl or "xsrf" in cl or c.name in CSRF_COOKIE_NAMES:
                log.info("  Using existing CSRF cookie %s (len=%d)", c.name, len(c.value))
                return c.value

        log.warning("  No CSRF found anywhere")
        return None
    except Exception as e:
        log.warning("  CSRF refresh failed: %s", e)
        return None


def get_api_session():
    """Create a requests.Session with all necessary headers for Zampto API.
    Honors ALL_PROXY/HTTPS_PROXY env vars (e.g. socks5h://127.0.0.1:1080)"""
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
    })
    # Auto-pick up proxy from env (set by workflow when TUIC is active)
    proxy_url = os.getenv("ALL_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
    if proxy_url:
        s.proxies.update({
            "http": proxy_url,
            "https": proxy_url,
        })
        log.info("API session using proxy: %s", proxy_url)
    return s


def fill_field_el(page, selector, value):
    try:
        el = page.query_selector(selector)
        if el:
            el.fill(value)
            log.info("Filled field with selector: %s", selector)
            return True
    except Exception as e:
        log.warning("Fill failed with %s: %e", selector, e)
    return False


def click_btn(page, selector):
    try:
        btn = page.query_selector(selector)
        if btn:
            btn.click()
            log.info("Clicked button with selector: %s", selector)
            return True
    except Exception as e:
        log.warning("Click failed with %s: %e", selector, e)
    return False


def solve_turnstile(page, max_wait=90, click_after=8):
    """等待 Cloudflare Turnstile 验证自动通过; 若超时未通过, 用坐标点击 iframe 复选框。

    行为:
      1. 检测到 Turnstile iframe (challenges.cloudflare.com) 后, 优先等待自动通过
         (用户确认多数情况下 managed 模式会自动通过)
      2. 若 iframe 持续存在超过 click_after 秒仍未消失, 用 page.mouse.click 坐标点击
         iframe 内复选框位置 (左上区域)
      3. 点击前先做随机鼠标移动 + 短停顿, 模拟真实用户行为 (避免 Cloudflare 检测自动化)
      4. 如果第一次坐标点击后 iframe 仍在 15s 内未消失, 再点击一次 (改用不同 offset)
      5. 整个流程上限 max_wait 秒

    跨域 iframe JS 不能直接 click 内部元素, 但 page.mouse.click 是浏览器层面的
    合成事件, 直接发送到 (x, y) 坐标, 不受同源策略限制, 因此可以"穿透" iframe。

    返回 True 表示验证已通过/无需验证, False 表示超时仍未通过。
    """
    import time as _time
    import random as _rand
    log.info("🎯 等待 Turnstile 自动验证通过 (最长 %ds, %ds 后尝试坐标点击)...", max_wait, click_after)
    deadline = _time.time() + max_wait
    iframe_first_seen = None
    last_click_at = None
    click_count = 0
    last_diag_dump = 0  # 限流: 每 15s 才 dump 一次诊断, 避免日志爆炸
    iframe_ready_logged = False

    def _find_iframe_box():
        """找到 Turnstile iframe 及其 bounding box, 找不到返回 None

        多策略查找 (按可靠性排序):
          A. 遍历 page.frames 找到 CF Turnstile frame, 用 frame.frame_element() 拿到
             iframe DOM 元素 (最可靠, 不依赖 src 属性匹配)
          B. query_selector 多种 src 选择器 (兜底, 兼容属性 src 与动态 src)
          C. 用 page.evaluate 在页面内遍历所有 iframe, 返回 boundingClientRect (最深入)
        """
        # 策略 A: 从 page.frames 反查 iframe DOM 元素
        try:
            for fr in page.frames:
                furl = (fr.url or "").lower()
                if "challenges.cloudflare.com" in furl or "turnstile" in furl:
                    try:
                        iframe_el = fr.frame_element()
                        if iframe_el:
                            box = iframe_el.bounding_box()
                            if box and box.get("width", 0) > 0 and box.get("height", 0) > 0:
                                return iframe_el, box
                    except Exception:
                        pass
        except Exception:
            pass

        # 策略 B: query_selector 多选择器
        for sel in [
            'iframe[src*="challenges.cloudflare.com"]',
            'iframe[src*="turnstile"]',
            'iframe[src*="cloudflare"]',
            'div.cf-turnstile iframe',
            'div[data-sitekey] iframe',
            'iframe[title*="Widget"]',
            'iframe[title*="Cloudflare"]',
        ]:
            try:
                iframe_el = page.query_selector(sel)
                if iframe_el:
                    box = iframe_el.bounding_box()
                    if box and box.get("width", 0) > 0 and box.get("height", 0) > 0:
                        return iframe_el, box
            except Exception:
                pass

        # 策略 C: 在页面内用 JS 遍历所有 iframe, 拿 boundingClientRect
        try:
            js_get_box = """
            (() => {
                const iframes = document.querySelectorAll('iframe');
                const results = [];
                for (const ifr of iframes) {
                    const r = ifr.getBoundingClientRect();
                    results.push({
                        src: ifr.src || ifr.getAttribute('src') || '',
                        title: ifr.title || '',
                        visible: ifr.offsetParent !== null || ifr.getClientRects().length > 0,
                        w: Math.round(r.width), h: Math.round(r.height),
                        x: Math.round(r.left), y: Math.round(r.top),
                    });
                }
                return JSON.stringify(results);
            })();
"""
            result = page.evaluate(js_get_box)
            import json as _ij
            iframe_list = _ij.loads(result) if result else []
            # 优先返回 cf-turnstile 容器 (可能 iframe 还没加载但容器有位置)
            for ifr in iframe_list:
                src = (ifr.get("src") or "").lower()
                title = (ifr.get("title") or "").lower()
                if (("challenges.cloudflare.com" in src or "turnstile" in src or
                     "widget" in title or "turnstile" in title or "cloudflare" in title)
                        and ifr.get("w", 0) > 0 and ifr.get("h", 0) > 0):
                    return None, {
                        "x": ifr["x"], "y": ifr["y"],
                        "width": ifr["w"], "height": ifr["h"],
                    }
            # cf-turnstile 容器即使 iframe 还没加载, 也可作为 fallback 点击点
            try:
                cf_box = page.evaluate("""
                (() => {
                    const cf = document.querySelector('.cf-turnstile, [data-sitekey]');
                    if (!cf) return null;
                    const r = cf.getBoundingClientRect();
                    if (r.width <= 0 || r.height <= 0) return null;
                    return JSON.stringify({x: r.left, y: r.top, w: r.width, h: r.height});
                })();
""")
                if cf_box:
                    box = _ij.loads(cf_box)
                    return None, {"x": box["x"], "y": box["y"], "width": box["w"], "height": box["h"]}
            except Exception:
                pass
        except Exception:
            pass

        return None, None

    def _dump_diag():
        """诊断: 打印当前页面所有 iframe 信息, 帮助定位为何找不到 bounding box"""
        try:
            diag = page.evaluate("""
            (() => {
                const iframes = document.querySelectorAll('iframe');
                const out = [];
                for (const ifr of iframes) {
                    const r = ifr.getBoundingClientRect();
                    out.push({
                        src: (ifr.src || '').slice(0, 100),
                        title: ifr.title || '',
                        visible: ifr.offsetParent !== null,
                        w: Math.round(r.width), h: Math.round(r.height),
                        x: Math.round(r.left), y: Math.round(r.top),
                    });
                }
                const cf = document.querySelector('.cf-turnstile, [data-sitekey]');
                const cfInfo = cf ? {
                    tag: cf.tagName, className: cf.className,
                    visible: cf.offsetParent !== null,
                    rect: cf.getBoundingClientRect().toJSON(),
                } : null;
                return JSON.stringify({iframes: out, cfContainer: cfInfo});
            })();
""")
            log.info("  [DIAG] %s", diag[:600])
        except Exception as e:
            log.warning("  [DIAG] 失败: %s", e)

    while _time.time() < deadline:
        try:
            # 1. 检查是否还有 Turnstile 痕迹
            has_frame = False
            try:
                for fr in page.frames:
                    furl = (fr.url or "").lower()
                    if "challenges.cloudflare.com" in furl or "turnstile" in furl:
                        has_frame = True
                        break
            except Exception:
                pass
            body_text = ""
            try:
                body_text = page.evaluate("document.body ? document.body.innerText : ''") or ""
            except Exception:
                pass
            has_verify = any(w in body_text.lower() for w in
                             ["security verification", "complete the security", "verification required",
                              "loading security", "please complete"])

            # 2. 验证已消失 -> 通过
            if not has_verify and not has_frame:
                if iframe_first_seen:
                    log.info("  ✅ Turnstile 已通过 (耗时 %.1fs)", _time.time() - iframe_first_seen)
                else:
                    log.info("  ✅ 未出现 Turnstile, 无需验证")
                return True

            # 3. 记录 iframe 首次出现时间 (但不立即 dump, 等 iframe 加载好)
            if has_frame and iframe_first_seen is None:
                iframe_first_seen = _time.time()
                log.info("  📍 Turnstile iframe 首次出现")

            # 3.5 等待 iframe 真正有尺寸 (3s 后再 dump 一次诊断, 此时 iframe 应已加载 src)
            if (has_frame and not iframe_ready_logged
                    and _time.time() - iframe_first_seen >= 3):
                iframe_ready_logged = True
                _dump_diag()

            # 4. 若等待已超过 click_after 秒仍未通过, 用坐标点击 iframe 复选框
            if (has_frame and iframe_first_seen is not None
                    and _time.time() - iframe_first_seen >= click_after):
                iframe_el, box = _find_iframe_box()
                if box:
                    # checkbox 在 Turnstile widget 左上区域
                    # 典型 widget 300x65 (compact) 或 130x120 (block), checkbox 约 30x30 在 x=10, y=18
                    # 多次点击尝试不同 offset, 找到正确的复选框位置
                    click_offsets = [
                        (max(20, box['width'] * 0.08), box['height'] * 0.30),  # 最左上, compact widget checkbox
                        (max(30, box['width'] * 0.10), box['height'] * 0.40),  # 标准位置
                        (max(15, box['width'] * 0.05), box['height'] * 0.25),  # 更左上
                    ]
                    off = click_offsets[click_count % len(click_offsets)]
                    target_x = box['x'] + off[0]
                    target_y = box['y'] + off[1]
                    try:
                        # 拟人化: 先随机移动几下, 短停顿, 再点击
                        for _ in range(2):
                            page.mouse.move(
                                box['x'] + _rand.uniform(50, max(100, box['width'])),
                                box['y'] + _rand.uniform(20, max(40, box['height'])),
                            )
                            _time.sleep(_rand.uniform(0.2, 0.5))
                        _time.sleep(_rand.uniform(0.3, 0.8))
                        page.mouse.click(target_x, target_y)
                        last_click_at = _time.time()
                        click_count += 1
                        log.info("  🖱️ 第 %d 次坐标点击 Turnstile checkbox (%.0f, %.0f) (iframe 大小 %.0fx%.0f offset %.2f,%.2f)",
                                 click_count, target_x, target_y, box['width'], box['height'], off[0], off[1])
                    except Exception as e:
                        log.warning("  坐标点击失败: %s", e)
                    # 第一次点击后等 15s 再决定是否重试, 避免太快连续点击被 CF 检测为自动化
                    if click_count == 1:
                        _time.sleep(15)
                        continue
                else:
                    # 限流诊断, 避免日志爆炸
                    if _time.time() - last_diag_dump > 15:
                        log.warning("  Turnstile iframe 找不到 bounding box (尝试多策略均失败)")
                        _dump_diag()
                        last_diag_dump = _time.time()

            _time.sleep(3)
        except Exception as e:
            log.warning("Turnstile 等待异常: %s", e)
            _time.sleep(2)

    # 超时退出
    if last_click_at:
        log.warning("⏰ Turnstile 已点击 %d 次但 %ds 内仍未通过", click_count, max_wait)
    else:
        log.warning("⏰ Turnstile 验证超时(%ds), 未能自动通过也未尝试点击", max_wait)
    return False


def wait_for_url_change(page, start_url, max_wait=30):
    """Poll until URL changes from start_url."""
    for i in range(max_wait):
        time.sleep(1)
        if page.url != start_url:
            log.info("URL changed to: %s", page.url)
            return True
    log.info("Max wait exceeded, still on %s", page.url)
    return False


def phase_browser_login_interactive():
    """Phase 1 (LOCAL ONLY): Interactive browser login with user-visible window."""
    log.info("=== INTERACTIVE BROWSER LOGIN ===")
    log.info("A browser window will open on your desktop. Please complete the following:")
    log.info("1. Enter your email and password")
    log.info("2. Solve the Cloudflare Turnstile CAPTCHA if prompted")
    log.info("3. Click the Login button")
    log.info("4. After successful login, close the browser window")
    log.info("")

    if not HAS_CLOAKBROWSER:
        raise RuntimeError("CloakBrowser not available - cannot run browser login")

    proxy = None
    if os.getenv("HY2_CONFIG", ""):
        proxy = {"server": "socks5://127.0.0.1:1080"}

    browser = launch(headless=False, proxy=proxy)  # headless=False for visible UI
    page = browser.new_page()

    start_url = f"{DASHBOARD_URL}/auth/login"
    log.info("Opening browser at: %s", start_url)
    page.goto(start_url, wait_until="domcontentloaded", timeout=90000)
    snap(page, "01_login_ready.png")

    # User handles everything manually in the visible browser
    input("Please complete login in the browser window, then press Enter to continue...")

    # Check if we're still on login page
    if "/auth/login" in page.url.lower():
        log.warning("Login appears to have failed - still on login page")
        snap(page, "01_login_failed.png")
    else:
        log.info("Login seems successful. URL is now: %s", page.url)
        snap(page, "01_login_success.png")

    # Save cookies
    cookies = page.context.cookies()
    save_session_cookies(cookies)
    browser.close()
    log.info("Interactive login completed. Session saved to session.json.")


# ========================
# Phase 2: 浏览器自动续期
# ========================
def renew_via_browser_fetch(page, sid, explicit_csrf=None):
    """在浏览器页面上下文中尝试刷新服务器。

    CSRF token 由浏览器自动管理，无需手动刷新。

    explicit_csrf: 若提供, 则优先使用此 token (绕过 document.cookie HttpOnly 限制)。
    浏览器 HttpOnly cookie JS 无法读取, 但 Playwright ctx.cookies() 可以,
    调用方应在 page.evaluate 之前从 ctx.cookies() 取出 zampto_csrf 注入此处。

    本次改进 (v3):
      - 不只试 explicit_csrf / meta / document.cookie, 还从 window 全局对象找
        Laravel app 常见位置: window.csrfToken, window.Laravel.csrfToken,
        window.axios.defaults.headers, document.querySelector('script[data-csrf]'),
        以及页面 JS 渲染的 Renew 按钮 onclick 中可能硬编码的 token
      - 详细诊断: 失败时打印 lastTokPrefix, attempts, lastStatus, lastRespBody,
        以及所有尝试过的 candidate prefixes
    """
    import json as _json
    bodies = [
        {"server_id": sid}, {"id": sid}, {"serverId": sid},
        {"server": sid}, {"sid": sid},
    ]
    # JS 函数, Playwright page.evaluate 会调用它并传入 args
    # args = {explicit_csrf, body}; 用 args 而非闭包变量, 是因为 page.evaluate 会把
    # 闭包变量序列化再反序列化, 但传 args 是 Playwright 原生支持的, 更可靠
    js_fn = r"""
async (args) => {
    try {
        const candidates = [];

        // 1. 显式传入的 explicit_csrf (来自 Playwright ctx.cookies() 取出的 HttpOnly cookie)
        if (args && args.explicit_csrf) {
            const t = String(args.explicit_csrf).trim();
            if (t) candidates.push({tok: t, src: 'explicit_csrf'});
        }

        // 2. meta[name="csrf-token"] (Laravel 标准)
        const meta = document.querySelector('meta[name="csrf-token"]');
        if (meta && meta.getAttribute('content')) {
            const m = meta.getAttribute('content').trim();
            if (m) candidates.push({tok: m, src: 'meta'});
        }
        // meta[name="csrf_token"] (有些项目用下划线)
        const meta2 = document.querySelector('meta[name="csrf_token"], meta[name="xsrf-token"]');
        if (meta2 && meta2.getAttribute('content')) {
            const m = meta2.getAttribute('content').trim();
            if (m) candidates.push({tok: m, src: 'meta_underscore'});
        }

        // 3. window 全局对象中找 CSRF token
        // Laravel 项目常见的全局: window.csrfToken, window.Laravel.csrfToken,
        // window.axios.defaults.headers.common['X-XSRF-TOKEN'], window.csrf
        try {
            if (window.csrfToken) candidates.push({tok: String(window.csrfToken).trim(), src: 'window.csrfToken'});
            if (window.Laravel && window.Laravel.csrfToken) candidates.push({tok: String(window.Laravel.csrfToken).trim(), src: 'window.Laravel.csrfToken'});
            if (window.csrf) candidates.push({tok: String(window.csrf).trim(), src: 'window.csrf'});
            if (window.axios && window.axios.defaults && window.axios.defaults.headers) {
                const h = window.axios.defaults.headers;
                const c = h.common || {};
                if (c['X-XSRF-TOKEN']) candidates.push({tok: String(c['X-XSRF-TOKEN']).trim(), src: 'axios.common.X-XSRF-TOKEN'});
                if (c['X-CSRF-TOKEN']) candidates.push({tok: String(c['X-CSRF-TOKEN']).trim(), src: 'axios.common.X-CSRF-TOKEN'});
                if (c['X-CSRF-Token']) candidates.push({tok: String(c['X-CSRF-Token']).trim(), src: 'axios.common.X-CSRF-Token'});
            }
        } catch(e) {}

        // 4. <script data-csrf="..." /> 形式 (Laravel Breeze / Jetstream 常见)
        try {
            const sc = document.querySelector('script[data-csrf], script[data-csrf-token]');
            if (sc) {
                const t = sc.getAttribute('data-csrf') || sc.getAttribute('data-csrf-token');
                if (t) candidates.push({tok: t.trim(), src: 'script[data-csrf]'});
            }
        } catch(e) {}

        // 5. document.cookie 中的 CSRF cookie (HttpOnly 读不到, 但有时不是 HttpOnly)
        const cookieParts = (document.cookie || '').split(';');
        for (const part of cookieParts) {
            const kv = part.trim().split('=');
            if (kv.length < 2) continue;
            const name = kv[0].trim();
            if (name === 'XSRF-TOKEN' || name === 'zampto_csrf' || /csrf/i.test(name)) {
                const raw = kv.slice(1).join('=');
                if (raw) candidates.push({tok: raw, src: 'cookie.' + name});
                try {
                    const dec = decodeURIComponent(raw);
                    if (dec && dec !== raw) candidates.push({tok: dec, src: 'cookie.' + name + '.decoded'});
                } catch(e) {}
                break;
            }
        }

        // 去重 (按 tok 值), 保留首次 src 标记
        const seen = new Set();
        const uniq = [];
        for (const c of candidates) {
            if (!seen.has(c.tok)) { seen.add(c.tok); uniq.push(c); }
        }

        // 报告所有 candidate 来源, 方便诊断
        const candSummary = uniq.map(c => c.src + ':' + c.tok.slice(0, 20)).join('|');

        const headerNames = ['X-XSRF-TOKEN', 'X-CSRF-TOKEN', 'X-CSRF-Token'];
        let lastTokHdr = null;
        let lastTokPrefix = null;
        let lastTokSrc = null;
        let lastRespBody = null;
        let lastStatus = null;
        let attempts = 0;
        for (const c of uniq) {
            const tok = c.tok;
            for (const hdr of headerNames) {
                attempts++;
                lastTokHdr = hdr;
                lastTokPrefix = tok.slice(0, 50);
                lastTokSrc = c.src;
                const res = await fetch('/api/server/renew', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        [hdr]: tok,
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    body: JSON.stringify(args.body),
                    credentials: 'include',
                });
                const text = await res.text();
                lastStatus = res.status;
                lastRespBody = text.slice(0, 200);
                const ok = [200, 201, 204, 202].includes(res.status);
                if (ok) return JSON.stringify({status: res.status, body: text, header: hdr, tokLen: tok.length, ok: true, tokSrc: c.src});
                if (res.status !== 403 || !/csrf/i.test(text)) {
                    return JSON.stringify({status: res.status, body: text, header: hdr, tokLen: tok.length, ok: false, final: true, tokSrc: c.src});
                }
            }
        }
        return JSON.stringify({
            status: -1,
            body: 'all csrf attempts failed',
            ok: false,
            attempts: attempts,
            candidates: uniq.length,
            candSummary: candSummary,
            cookie_readable: document.cookie ? 'yes' : 'no',
            lastTokHdr: lastTokHdr,
            lastTokPrefix: lastTokPrefix,
            lastTokSrc: lastTokSrc,
            lastStatus: lastStatus,
            lastRespBody: lastRespBody,
        });
    } catch(e) {
        return JSON.stringify({status: 0, body: e.message, ok: false});
    }
}
"""
    for body in bodies:
        try:
            args_obj = {"explicit_csrf": explicit_csrf or "", "body": body}
            result = page.evaluate(js_fn, args_obj)
            data = _json.loads(result)
            if data.get("status") == -1:
                log.info("  fetch /api/server/renew body=%s -> HTTP -1 resp=%s",
                         body, str(data.get("body", ""))[:200])
                log.info("    [DIAG] attempts=%s candidates=%s cookie_readable=%s candSummary=%s",
                         data.get("attempts"), data.get("candidates"), data.get("cookie_readable"),
                         data.get("candSummary"))
                log.info("    [DIAG] lastTokHdr=%s lastTokPrefix=%r lastTokSrc=%s lastStatus=%s lastRespBody=%s",
                         data.get("lastTokHdr"), data.get("lastTokPrefix"),
                         data.get("lastTokSrc"), data.get("lastStatus"),
                         str(data.get("lastRespBody", ""))[:150])
            else:
                tok_src = data.get("tokSrc", "")
                log.info("  fetch /api/server/renew body=%s -> HTTP %s (header=%s tokLen=%s tokSrc=%s) resp=%s",
                         body, data.get("status"), data.get("header"), data.get("tokLen"),
                         tok_src, str(data.get("body", ""))[:200])
            if data.get("status") in (200, 201, 204, 202):
                return True, data
            # 非 403 或业务错误: 说明 CSRF 已通过, 继续试其他 body 无意义
            if data.get("final") or (data.get("status") not in (403, -1, 0)):
                log.warning("  CSRF 已通过但业务失败(status=%s tokSrc=%s), 停止尝试",
                             data.get("status"), data.get("tokSrc"))
                break
        except Exception as e:
            log.warning("  fetch attempt failed: %s", e)
    return False, None


def query_renewal_field(cookies=None, page=None):
    """查询服务器 renewal 字段 (上次续期时间, 到期 = renewal + 48h)。

    优先用浏览器上下文 fetch (带 Cloudflare token, 最可靠),
    失败则回退 requests. 返回 renewal 原始字符串, 查不到返回 None.
    """
    # 方式1: 浏览器上下文 fetch (带 CF token)
    if page is not None:
        try:
            js = """
            (async () => {
                try {
                    const res = await fetch('/api/servers', {headers: {'Accept': 'application/json'}});
                    if (!res.ok) return JSON.stringify({ok: false, status: res.status});
                    const j = await res.json();
                    return JSON.stringify({ok: true, data: j});
                } catch(e) { return JSON.stringify({ok: false, error: e.message}); }
            })();
            """
            result = page.evaluate(js)
            data = json.loads(result)
            if data.get("ok"):
                j = data["data"]
                for sv in (j.get("servers") or []):
                    if str(sv.get("id")) == str(SERVER_ID):
                        return sv.get("renewal")
        except Exception as e:
            log.warning("浏览器查询 renewal 失败: %s", e)
    # 方式2: requests
    if cookies:
        try:
            api = get_api_session()
            sync_cookies_to_session(api, cookies)
            r = api.get(f"{DASHBOARD_URL}/api/servers", timeout=10)
            if r.status_code == 200:
                for sv in (r.json().get("servers") or []):
                    if str(sv.get("id")) == str(SERVER_ID):
                        return sv.get("renewal")
        except Exception as e:
            log.warning("requests 查询 renewal 失败: %s", e)
    return None


def phase_browser_renewal(cookies=None):
    """Phase 2: 浏览器自动续期。
    返回: "renewed" / "skipped" / "failed" """
    log.info("=== BROWSER RENEWAL MODE ===")
    if not HAS_CLOAKBROWSER:
        log.error("CloakBrowser not available")
        return "failed"

    if not cookies:
        cookies = load_session()
    if not cookies:
        log.error("No cookies available")
        return "failed"

    # 记录续期前的 renewal (上次续期时间), 用于点击后对比验证
    baseline_renewal = None
    try:
        api = get_api_session()
        sync_cookies_to_session(api, cookies)
        r = api.get(f"{DASHBOARD_URL}/api/servers", timeout=10)
        if r.status_code == 200:
            for sv in (r.json().get("servers") or []):
                if str(sv.get("id")) == str(SERVER_ID):
                    exp_raw = sv.get("renewal", "")
                    baseline_renewal = exp_raw or None
                    if exp_raw:
                        from datetime import datetime as dt_cls, timedelta
                        dt_ob = dt_cls.fromisoformat(exp_raw.replace("Z", "+00:00"))
                        expires_at = dt_ob + timedelta(hours=48)
                        rem_h = (expires_at - datetime.now(timezone.utc)).total_seconds() / 3600
                        if not FORCE_RENEW and rem_h > RENEW_THRESHOLD_HOURS:
                            log.info("剩余 %.0fh (>%dh), 跳过续期", rem_h, RENEW_THRESHOLD_HOURS)
                            return "skipped"
                        if FORCE_RENEW:
                            log.info("剩余 %.0fh, FORCE_RENEW=true 强制续期", rem_h)
    except Exception as e:
        log.warning("预检查剩余时间失败(可能被CF拦截): %s", e)
    log.info("续期前 renewal: %r", baseline_renewal)

    log.info("Launching CloakBrowser headless...")
    proxy = None
    if os.environ.get("ALL_PROXY") or os.environ.get("HTTPS_PROXY"):
        proxy = {"server": "socks5://127.0.0.1:1080"}

    try:
        browser = launch(headless=True, proxy=proxy)
        ctx = browser.new_context(no_viewport=True)
        page = ctx.new_page()

        # 注入 cookies
        for c in cookies:
            try:
                cookie = {
                    "name": c["name"],
                    "value": c["value"],
                    "path": c.get("path", "/"),
                    "secure": c.get("secure", True),
                }
                if c["name"].startswith("__Host-"):
                    # __Host- 前缀: 不能含 domain 属性, 必须 path="/", secure=True
                    # Playwright add_cookies 用 url 指定作用域即可, 不能设 domain
                    pass
                else:
                    cookie["domain"] = c.get("domain", ".zampto.net")
                ctx.add_cookies([cookie])
            except Exception as e:
                log.warning("  skip cookie %s: %s", c["name"], e)

        # 验证注入结果: 打印浏览器实际 cookie 名 (确认 XSRF-TOKEN/session 是否注入成功)
        # 同时从 ctx.cookies() 取出 CSRF token (HttpOnly cookie JS 读不到, 但 Playwright 可以)
        browser_csrf_token = None
        try:
            real_cookies = ctx.cookies()
            real_names = [ck["name"] for ck in real_cookies]
            log.info("📋 浏览器实际 Cookies(%d): %s", len(real_names), real_names)
            # 找 CSRF cookie (HttpOnly 也能读到); 优先 zampto_csrf, 兜底其他名称
            csrf_cookie_names = ["zampto_csrf", "XSRF-TOKEN", "__Host-zampto_csrf", "__Host-XSRF-TOKEN", "csrf_token", "xsrf_token"]
            csrf_cookie = next((ck for ck in real_cookies if ck["name"] in csrf_cookie_names), None)
            if csrf_cookie:
                browser_csrf_token = csrf_cookie["value"]
                log.info("🔑 浏览器 CSRF cookie %s (len=%d, httpOnly=%s) 已取出, 将注入 fetch",
                         csrf_cookie["name"], len(browser_csrf_token), csrf_cookie.get("httpOnly"))
            else:
                log.warning("⚠️ 浏览器未找到 CSRF cookie (HttpOnly cookie 也读不到) - 将依赖 document.cookie")
        except Exception as e:
            log.warning("读取浏览器 cookie 失败: %s", e)

        # v3 关键改进: 在浏览器上注册 request/response 监听, 捕获页面自身 JS 发的
        # /api/server/renew 请求. 这样:
        #   1) 如果页面 Renew 按钮 click 触发了实际的 renew 请求, 我们能捕获它用的
        #      header (包括正确的 X-XSRF-TOKEN 来源), 用来诊断我们的 fetch 哪里错
        #   2) 如果请求成功, 我们直接从响应判断是否续期成功, 无需 query_renewal_field
        captured_renew_requests = []
        captured_renew_responses = []
        try:
            def _on_request(req):
                try:
                    if "/api/server/renew" in req.url and req.method == "POST":
                        captured_renew_requests.append({
                            "url": req.url,
                            "method": req.method,
                            "headers": dict(req.headers),
                            "post_data": req.post_data,
                        })
                        log.info("📡 [INTERCEPT] 页面发了 renew 请求: %s %s headers=%s post_data=%s",
                                 req.method, req.url, list(req.headers.keys()),
                                 (req.post_data or "")[:200])
                except Exception:
                    pass
            def _on_response(resp):
                try:
                    if "/api/server/renew" in resp.url and resp.request.method == "POST":
                        try:
                            body = resp.text()
                        except Exception:
                            body = "<binary>"
                        captured_renew_responses.append({
                            "url": resp.url,
                            "status": resp.status,
                            "headers": dict(resp.headers),
                            "body": body[:500],
                        })
                        log.info("📥 [INTERCEPT] renew 响应: HTTP %d body=%s",
                                 resp.status, body[:200])
                except Exception:
                    pass
            page.on("request", _on_request)
            page.on("response", _on_response)
            log.info("🔌 已注册 request/response 监听器 (用于捕获页面自身 renew 请求)")
        except Exception as e:
            log.warning("注册 request/response 监听器失败(可忽略): %s", e)

        # 访问面板主页
        log.info("导航到 %s ...", DASHBOARD_URL)
        page.goto(DASHBOARD_URL, wait_until="load", timeout=30000)
        page.wait_for_timeout(3000)
        snap(page, "02_dashboard.png")

        if "/auth/login" in page.url:
            log.error("需要重新登录 - Cookie 已过期")
            browser.close()
            return False

        log.info("面板加载完成, URL: %s", page.url)

        # 转到服务器详情页（续期按钮在这里）
        server_url = f"{DASHBOARD_URL}/server?id={SERVER_ID}"
        log.info("导航到服务器页: %s", server_url)
        page.goto(server_url, wait_until="load", timeout=30000)
        page.wait_for_timeout(3000)
        snap(page, "03_server_page.png")
        log.info("服务器页加载完成, URL: %s", page.url)

        # 执行续期
        sid = SERVER_ID
        # 在导航到服务器页之后, 浏览器可能已用新 Set-Cookie 覆盖了注入的 CSRF cookie
        # 重新从 ctx.cookies() 读取最新的 token, 确保 explicit_csrf 是当前最新值
        try:
            real_cookies2 = ctx.cookies()
            csrf_cookie_names = ["zampto_csrf", "XSRF-TOKEN", "__Host-zampto_csrf", "__Host-XSRF-TOKEN", "csrf_token", "xsrf_token"]
            csrf_cookie2 = next((ck for ck in real_cookies2 if ck["name"] in csrf_cookie_names), None)
            if csrf_cookie2:
                if browser_csrf_token != csrf_cookie2["value"]:
                    log.info("🔄 页面加载后 CSRF cookie 已更新 (len %d -> %d), 使用最新值",
                             len(browser_csrf_token or ""), len(csrf_cookie2["value"]))
                browser_csrf_token = csrf_cookie2["value"]
        except Exception as e:
            log.warning("刷新 CSRF cookie 失败(可忽略): %s", e)

        renewed, data = renew_via_browser_fetch(page, sid, explicit_csrf=browser_csrf_token)
        if renewed:
            log.info("续期成功! response: %s", data.get("body", "")[:200])
            browser.close()
            return "renewed"

        # 如果 fetch 失败, 尝试从页面找续期按钮
        log.info("fetch 失败, 尝试在页面中寻找 Renew 按钮...")
        try:
            # 先移除可能存在的 Cookie 同意弹窗 (fc-consent-root 会拦截点击)
            # 注意: 只删除顶层容器, 不要用 [class*="fc-consent"] 通配 (会误删页面 UI)
            try:
                removed = page.evaluate("""
                (() => {
                    const roots = document.querySelectorAll('.fc-consent-root, #onetrust-consent-sdk');
                    let n = 0;
                    roots.forEach(el => { el.remove(); n++; });
                    // 兜底: 移除可见的 dialog/overlay 弹窗
                    const overlays = document.querySelectorAll('div[role="dialog"], .fc-dialog-overlay');
                    overlays.forEach(el => { if (el.offsetParent !== null || el.getClientRects().length) { el.remove(); n++; } });
                    return n;
                })();
                """)
                if removed:
                    log.info("🍪 已移除 Cookie 弹窗容器: %d 个", removed)
                    page.wait_for_timeout(500)
            except Exception as e:
                log.warning("移除 Cookie 弹窗失败(可忽略): %s", e)

            renew_btn = page.query_selector('button:has-text("Renew"), a:has-text("Renew"), [data-action="renew"], #renew-btn')
            if renew_btn:
                log.info("找到了 Renew 按钮, 点击...")
                # 用 JS 直接触发 click, 避免被 Cookie 弹窗 overlay 拦截
                try:
                    renew_btn.evaluate("(el) => { el.click(); return true; }")
                    log.info("JS click 成功")
                except Exception:
                    renew_btn.click(force=True)
                    log.info("force click 成功")
                page.wait_for_timeout(3000)
                snap(page, "03_after_renew.png")
                # 处理 Turnstile 安全验证 (Zampto 续期需要人机验证)
                # v3 solve_turnstile: 先等 8s 自动通过, 失败后多次坐标点击 iframe checkbox (不同 offset)
                turnstile_ok = solve_turnstile(page, max_wait=90, click_after=8)
                if not turnstile_ok:
                    log.warning("Turnstile 90s 内未通过 (已尝试多次坐标点击), 继续验证 renewal 变化...")
                page.wait_for_timeout(3000)
                snap(page, "04_after_verify.png")
                log.info("按钮点击完成, 等待 3s 后验证续期结果...")
                page.wait_for_timeout(3000)

                # v3 关键改进: 优先用拦截器捕获的 renew 响应判断结果 (最可靠)
                # 1) 页面自身 JS 发的 renew 请求结果 (有则最权威, 直接看 status + body)
                if captured_renew_responses:
                    log.info("📥 拦截到 %d 个 renew 响应, 详情:", len(captured_renew_responses))
                    for i, r in enumerate(captured_renew_responses):
                        log.info("  [%d] HTTP %s body=%s", i, r["status"], r["body"][:200])
                    # 任一 200/201/204 = 续期成功
                    if any(r["status"] in (200, 201, 204, 202) for r in captured_renew_responses):
                        # 打印页面 JS 用的 headers, 帮我下次复现正确路径
                        for i, req in enumerate(captured_renew_requests):
                            log.info("  [REQ %d] url=%s headers=%s post_data=%s",
                                     i, req["url"], req["headers"], req["post_data"])
                        browser.close()
                        log.info("✅ 续期成功 (页面 JS 触发的 renew 请求成功)")
                        return "renewed"

                # 验证续期是否真的生效: 重新查询 renewal, 与点击前对比
                new_renewal = query_renewal_field(cookies=cookies, page=page)
                log.info("续期后 renewal: %r (点击前: %r)", new_renewal, baseline_renewal)
                browser.close()
                if new_renewal and new_renewal != baseline_renewal:
                    log.info("✅ 续期确认成功: renewal 已更新")
                    return "renewed"
                log.error("❌ 续期失败: 点击后 renewal 未变化, 续期未生效")
                return "failed"
            else:
                log.info("页面中未找到 Renew 按钮 - 需要手动检查页面")
                snap(page, "03_no_renew_btn.png")
        except Exception as e:
            log.warning("查找续期按钮失败: %s", e)

        snap(page, "03_renew_result.png")
        browser.close()
        # 没找到按钮: 再查一次 renewal 看是否已变化(可能 fetch 已成功但未识别)
        final_renewal = query_renewal_field(cookies=cookies)
        if final_renewal and final_renewal != baseline_renewal:
            log.info("✅ 续期确认成功: renewal 已更新 (fetch 路径)")
            return "renewed"
        log.error("❌ 续期失败: 未找到续期按钮且 renewal 未变化")
        return "failed"
    except Exception as e:
        log.error("Browser mode failed: %s", e)
        return "failed"

def phase_api_renewal(use_cookies=None):
    """Phase 3: Use provided cookies to renew server via pure API (no browser)."""
    log.info("=== PURE API RENEWAL MODE ===")
    cookies = use_cookies or []

    if not cookies:
        log.error("No valid cookies/session available - cannot proceed")
        return False

    log.info("Using %d cookies for API authentication", len(cookies))
    api_session = get_api_session()
    sync_cookies_to_session(api_session, cookies)

    # IMPORTANT: Do NOT set X-CSRF-Token in api_session.headers!
    # The server issues a NEW CSRF cookie on EVERY response (old value expires immediately).
    # If we set it once in session.headers, it becomes stale after the first GET.
    # Instead, we'll fetch the latest cookie value right before each POST and pass it
    # as a per-request header.
    csrf_token = find_csrf_cookie(cookies)
    if csrf_token:
        log.info("Initial CSRF cookie found (length=%d, will refresh before POST)", len(csrf_token))
    else:
        log.warning("No CSRF cookie in initial session - will fetch from server")

    # Add browser-like headers to satisfy Cloudflare and SameSite CSRF checks
    api_session.headers.update({
        "Referer": f"{DASHBOARD_URL}/",
        "Origin": DASHBOARD_URL,
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    })

    # Pre-define report so error handlers can use it
    report = {
        "server_id": SERVER_ID,
        "status": "unknown",
        "action": "none",
        "expiry": None,
        "error": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Verify session by checking a safe endpoint
    try:
        test_resp = api_session.get(f"{DASHBOARD_URL}/auth/login", timeout=10)
        if test_resp.status_code == 200 and "antialiased" in test_resp.text[:500]:
            log.info("Session verified - authenticated")
        else:
            log.warning("Unexpected response from login page: %d, body[:200]=%s", test_resp.status_code, test_resp.text[:200])
    except Exception as e:
        log.error("Session verification failed: %s", e)

    # Fetch server info - probe multiple candidate paths if first one fails
    try:
        # Candidate API paths in order of likelihood
        candidate_paths = [
            f"/api/server/{SERVER_ID}",
            f"/api/servers/{SERVER_ID}",
            f"/api/server?server_id={SERVER_ID}",
            f"/api/server?id={SERVER_ID}",
            f"/api/v1/server/{SERVER_ID}",
            f"/api/v1/servers/{SERVER_ID}",
            f"/api/v2/server/{SERVER_ID}",
            f"/api/dashboard/server/{SERVER_ID}",
            f"/api/dashboard/servers/{SERVER_ID}",
            f"/api/user/servers/{SERVER_ID}",
            f"/api/account/servers/{SERVER_ID}",
            # List endpoints (will need to find server in list)
            "/api/servers",
            "/api/server",
            "/api/dashboard/servers",
            "/api/user/servers",
            "/api/account/servers",
        ]

        server_url = None
        server_data = None
        used_path = None

        for path in candidate_paths:
            url = f"{DASHBOARD_URL}{path}"
            log.info("Probing: %s", path)
            try:
                resp = api_session.get(url, timeout=15)
                ct = resp.headers.get("content-type", "")
                is_json = "json" in ct.lower()
                log.info("  -> %d %s (len=%d)", resp.status_code, "JSON" if is_json else "HTML", len(resp.text))

                # 200 + JSON = success
                if resp.status_code == 200 and is_json:
                    server_url = url
                    used_path = path
                    server_data = resp.json()
                    log.info("  ✓ Found valid API endpoint!")
                    break

                # 404 + HTML = path doesn't exist, try next
                if resp.status_code == 404 and not is_json:
                    continue

                # 403 + JSON = path exists but VPN/IP blocked
                if resp.status_code == 403 and is_json:
                    log.warning("  Path exists but blocked: %s", resp.text[:200])
                    # The path is correct but we can't access via current IP
                    # If proxy is configured, this shouldn't happen
                    continue

                # Other errors - log and continue
                log.warning("  Unexpected: %d body[:200]=%s", resp.status_code, resp.text[:200])
            except requests.exceptions.RequestException as e:
                log.warning("  Request failed: %s", e)
                continue

        if not server_data:
            log.error("Could not find a working API endpoint for server info")
            log.error("Probed %d paths, none returned 200+JSON", len(candidate_paths))
            report["error"] = "No working API endpoint found. Probed paths: " + ", ".join(candidate_paths[:5]) + "..."
            _report(report)
            return False

        log.info("Using endpoint: %s", used_path)
        log.info("Server data received (truncated): %s", json.dumps(server_data, indent=2, ensure_ascii=False)[:800])

        # Parse status - response shape can be:
        #   {"servers": [...]} - Zampto list endpoint
        #   {"data": {...}} or {"data": [...]} - Pterodactyl/other
        #   {...} - direct server object
        if isinstance(server_data, dict):
            if "servers" in server_data:
                # Zampto list endpoint - find our server by ID
                servers_list = server_data["servers"]
                log.info("Got %d servers, looking for ID=%s", len(servers_list), SERVER_ID)
                state_info = next(
                    (s for s in servers_list if str(s.get("id")) == str(SERVER_ID)),
                    servers_list[0] if servers_list else {}
                )
            elif "data" in server_data:
                state_info = server_data["data"]
                if isinstance(state_info, list):
                    state_info = next(
                        (s for s in state_info if str(s.get("id")) == str(SERVER_ID)),
                        state_info[0] if state_info else {}
                    )
            else:
                # Direct server object
                state_info = server_data
        else:
            state_info = {}

        if not isinstance(state_info, dict):
            state_info = {}

        # Extract identifier (8-char short UUID, e.g. 'f8a96d6e')
        server_identifier = state_info.get("identifier")
        log.info("Server identifier: %s", server_identifier)

        # Status - Zampto uses 'status' field directly with value 'active'/'offline'
        status_state = ""
        raw_status = state_info.get("status", "")
        if isinstance(raw_status, dict):
            status_state = raw_status.get("state", "").lower()
        elif raw_status:
            status_state = str(raw_status).lower()
        # Zampto: 'active' means running, 'offline'/'suspended' means stopped
        is_running = status_state in ["running", "started", "active", "online"]
        log.info("Raw status field: %r -> state=%s -> is_running=%s", raw_status, status_state, is_running)

        report.update({
            "status": "running" if is_running else "stopped",
            "action": "none",
            "expiry": None,
            "error": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        log.info("Server status: %s", report["status"])

        # Start if stopped
        started = False
        if not is_running:
            log.info("Server is stopped, attempting to start...")
            # Try both Pterodactyl-style and custom paths
            start_paths = []
            if server_identifier:
                start_paths.extend([
                    f"/api/client/servers/{server_identifier}/power",
                ])
            start_paths.extend([
                f"/api/servers/{SERVER_ID}/start",
                f"/api/servers/start",
                f"/api/server/{SERVER_ID}/start",
                f"/api/server/{SERVER_ID}/power",
                f"/api/servers/{SERVER_ID}/power",
            ])
            for start_path in start_paths:
                start_url = f"{DASHBOARD_URL}{start_path}"
                log.info("  Trying start endpoint: %s", start_path)

                # CRITICAL: Fetch fresh CSRF token right before each POST.
                # Server issues new cookie on every response, old value expires immediately.
                fresh_csrf = refresh_csrf_token(api_session)
                if not fresh_csrf:
                    log.warning("  Could not refresh CSRF, skipping this path")
                    continue

                # Pterodactyl expects JSON body {signal: 'start'}
                post_body = {"signal": "start"} if "/client/servers/" in start_path else {}
                # Pass CSRF token as PER-REQUEST header (not session.headers)
                # to ensure it matches the latest cookie value
                resp = api_session.post(
                    start_url,
                    json=post_body,
                    timeout=15,
                    headers={"X-CSRF-Token": fresh_csrf},
                )
                if resp.status_code in [200, 201, 204, 202]:
                    report["action"] = "started"
                    log.info("  ✓ Server start initiated (status %d)", resp.status_code)
                    is_running = True
                    report["status"] = "running"
                    started = True
                    break
                else:
                    log.warning("  Start failed at %s: %d %s", start_path, resp.status_code, resp.text[:200])
            if not started:
                report["error"] = "Start failed on all probed endpoints"

        # Check expiry and renew - always run this check (even if server was already running)
        # Action "none" means no action taken yet, "started" means just started.
        # Either way, we need to check if renewal is required.
        if report["action"] in ("started", "skipped", "none"):
            # Zampto 字段含义: renewal = 上次续期时间, 到期时间 = renewal + 48h
            expiry_val = None
            if isinstance(state_info, dict):
                if state_info.get("expiry"):
                    expiry_val = state_info["expiry"]
                elif state_info.get("renewal"):
                    expiry_val = state_info["renewal"]
            is_renewal_field = isinstance(state_info, dict) and bool(state_info.get("renewal")) and not bool(state_info.get("expiry"))
            if expiry_val:
                report["expiry"] = str(expiry_val)
                # Parse hours - support ISO datetime or "X days Y hours" string
                total_h = None
                # Try ISO datetime (e.g. "2026-07-30T12:28:33.000Z")
                iso_match = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', str(expiry_val))
                if iso_match:
                    try:
                        from datetime import datetime as dt_cls, timedelta as _td
                        expiry_dt = dt_cls.fromisoformat(iso_match.group(1).replace("Z", "+00:00"))
                        # 若字段是 renewal (上次续期时间), 到期时间 = renewal + 48h
                        if is_renewal_field:
                            expiry_dt = expiry_dt + _td(hours=48)
                            log.info("字段是 renewal, 到期时间 = renewal+48h")
                        now_dt = datetime.now(timezone.utc)
                        if expiry_dt.tzinfo is None:
                            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                        delta = expiry_dt - now_dt
                        total_h = max(0, int(delta.total_seconds() // 3600))
                        log.info("Expiry (ISO): %s => %d hours remaining (now=%s)", expiry_val, total_h, now_dt.isoformat())
                    except Exception as e:
                        log.warning("Failed to parse ISO datetime %s: %s", expiry_val, e)
                        total_h = 0  # Treat as expired -> renew

                # Fallback to string parsing (e.g. "3 days 5 hours")
                if total_h is None:
                    m = re.search(r'(\d+)\s*(?:day|d|天)', str(expiry_val), re.IGNORECASE)
                    h = re.search(r'(\d+)\s*(?:hour|h|小时)', str(expiry_val), re.IGNORECASE)
                    days = int(m.group(1)) if m else 0
                    hours = int(h.group(1)) if h else 0
                    total_h = days * 24 + hours
                    log.info("Expiry (string): %s = %d days %d h = %d h total", expiry_val, days, hours, total_h)

                should_renew = FORCE_RENEW or total_h < RENEW_THRESHOLD_HOURS
                if should_renew:
                    log.info("Renewing server (%d h left, threshold: %dh)", total_h, RENEW_THRESHOLD_HOURS)
                    renewed = False
                    # Confirmed correct endpoint: POST /api/server/renew
                    # Body field name unknown - try multiple variants
                    # Note: server may also require captcha (cf-turnstile-response)
                    renew_url = f"{DASHBOARD_URL}/api/server/renew"

                    # Try multiple body shapes - the API said "Invalid server ID"
                    # so we need to find the correct field name
                    body_variants = [
                        {"server_id": int(SERVER_ID) if SERVER_ID.isdigit() else SERVER_ID},
                        {"id": int(SERVER_ID) if SERVER_ID.isdigit() else SERVER_ID},
                        {"serverId": int(SERVER_ID) if SERVER_ID.isdigit() else SERVER_ID},
                        {"server": int(SERVER_ID) if SERVER_ID.isdigit() else SERVER_ID},
                        {"sid": int(SERVER_ID) if SERVER_ID.isdigit() else SERVER_ID},
                        {"server_id": SERVER_ID},  # string form
                        {"id": SERVER_ID},  # string form
                    ]

                    for body in body_variants:
                        log.info("  Trying /api/server/renew with body: %s", body)
                        fresh_csrf = refresh_csrf_token(api_session)
                        if not fresh_csrf:
                            continue
                        # 首个 body: 打印 CSRF 前缀 + 现有 session cookies 名, 帮助诊断
                        if body is body_variants[0]:
                            log.info("  [DIAG] csrf_token prefix=%r len=%d, session cookies=%s",
                                     fresh_csrf[:50], len(fresh_csrf),
                                     [(c.name, len(c.value), c.domain) for c in api_session.cookies])
                        try:
                            # Laravel 机制: zampto_csrf cookie 值是加密+URL编码的 token。
                            # - 浏览器存的是已 URL-decode 的值 (Playwright 会自动 decode)
                            # - requests 的 session.cookies 通常保留原始 (可能 URL-encoded) 形式
                            # - Laravel VerifyCsrfToken 会对 X-XSRF-TOKEN 调用 rawurldecode,
                            #   再 decrypt; 对 X-CSRF-Token 则期望明文 token (我们解不出)
                            # 因此我们尝试三种形式: 原始 / URL-encoded (safe='') / URL-decoded,
                            # 覆盖各种可能的 cookie 存储形式, Laravel 至少有一种能成功 decrypt
                            import urllib.parse as _up
                            token_variants = [fresh_csrf]
                            try:
                                enc = _up.quote(fresh_csrf, safe='')
                                if enc and enc != fresh_csrf:
                                    token_variants.append(enc)
                            except Exception:
                                pass
                            try:
                                dec = _up.unquote(fresh_csrf)
                                if dec and dec != fresh_csrf:
                                    token_variants.append(dec)
                            except Exception:
                                pass
                            # 兜底: 把 token 末尾的 = 去掉 / 加上一个 =, 模拟 base64 padding 差异
                            try:
                                if fresh_csrf.endswith("="):
                                    pad_stripped = fresh_csrf.rstrip("=")
                                    if pad_stripped not in token_variants:
                                        token_variants.append(pad_stripped)
                                else:
                                    # 长度不是 4 的倍数时补 =
                                    rem = len(fresh_csrf) % 4
                                    if rem:
                                        pad_added = fresh_csrf + "=" * (4 - rem)
                                        if pad_added not in token_variants:
                                            token_variants.append(pad_added)
                            except Exception:
                                pass
                            if body is body_variants[0]:
                                log.info("  [DIAG] token_variants=%d (raw/enc/dec/pad)", len(token_variants))
                            # X-XSRF-TOKEN 是 Laravel 标准 header, X-CSRF-Token 备选
                            header_variants = ["X-XSRF-TOKEN", "X-CSRF-Token"]
                            renew_success = False
                            for hdr in header_variants:
                                for tok in token_variants:
                                    try:
                                        resp = api_session.post(
                                            renew_url,
                                            json=body,
                                            timeout=15,
                                            headers={hdr: tok},
                                        )
                                        ct = resp.headers.get("content-type", "")
                                        is_json = "json" in ct.lower()
                                        # variant 标签: raw / enc / dec / pad_stripped / pad_added
                                        if tok == fresh_csrf:
                                            vtag = "raw"
                                        elif tok == _up.quote(fresh_csrf, safe=''):
                                            vtag = "enc"
                                        elif tok == _up.unquote(fresh_csrf):
                                            vtag = "dec"
                                        elif fresh_csrf.endswith("=") and tok == fresh_csrf.rstrip("="):
                                            vtag = "pad_stripped"
                                        else:
                                            vtag = "pad_added"
                                        log.info("    -> %d %s body=%s [%s len=%d variant=%s]",
                                                 resp.status_code, "JSON" if is_json else "HTML",
                                                 resp.text[:200], hdr, len(tok), vtag)

                                        if resp.status_code in [200, 201, 204, 202]:
                                            report["action"] = "renewed"
                                            log.info("  ✓ Renewal successful (status %d, body=%s, hdr=%s)", resp.status_code, body, hdr)
                                            renewed = True
                                            renew_success = True
                                            break
                                        # CSRF 失败换下一个组合; 其他业务错误(如冷却期)则停止
                                        if resp.status_code != 403 or "csrf" not in resp.text.lower():
                                            renew_success = True  # CSRF 已通过, 是业务错误
                                            break
                                    except Exception as e:
                                        log.warning("    Request failed (%s %s): %s", hdr, tok[:20], e)
                                if renew_success:
                                    break
                            if renew_success:
                                break
                            # If response says "Invalid server ID", try next variant
                            # If response says "captcha", we have a different problem
                            if "captcha" in resp.text.lower() or "verification" in resp.text.lower():
                                log.warning("    API requires captcha - cannot auto-renew without solving Turnstile")
                                report["error"] = "Captcha required: " + resp.text[:200]
                                break  # Don't try more variants, captcha is the blocker
                        except Exception as e:
                            log.warning("    Request failed: %s", e)

                    if not renewed and not report.get("error"):
                        report["error"] = "Renewal failed - could not find correct body format"
                else:
                    report["action"] = "skipped"
                    log.info("Not renewing - %d hours remaining (threshold: 48)", total_h)
            else:
                report["action"] = "skipped"
                log.warning("No expiry field in API response")

        # If captcha is required, treat as informational (not failure)
        # User has a userscript for manual/semi-auto renewal via browser
        if report.get("error") and "captcha" in str(report["error"]).lower():
            log.info("ℹ️ Captcha required - please use the userscript in your browser to renew")
            log.info("    The script will continue to monitor and send Telegram reminders")
            # Don't fail - this is expected behavior
            report["action"] = "manual_renewal_required"
            report["error"] = None
        # 只发一次报告（放到 captcha 判断之后，避免重复推送）
        _report(report)
        return True

    except requests.exceptions.RequestException as e:
        log.error("API request error: %s", e)
        report["error"] = f"API request failed: {str(e)}"
        _report(report)
        return False
    except Exception as e:
        log.error("API renewal failed unexpectedly: %s", e)
        report["error"] = str(e)
        _report(report)
        return False


def _report(report):
    status_icon = "\U0001F7E2" if report["status"] == "running" else "\U0001F534"
    action_icons = {
        "started": "▶️", "renewed": "🔄", "skipped": "⏭️",
        "renew-failed": "⚠️", "none": "📋",
        "start-failed": "❓", "login-failed": "🔒",
        "manual_renewal_required": "🔔",
    }
    action_cn = {
        "started": "已启动", "renewed": "已续期", "skipped": "已跳过",
        "none": "无操作", "manual_renewal_required": "需手动续期",
    }
    status_cn = "运行中" if report["status"] == "running" else "已停止"
    action_text = action_cn.get(report["action"], report["action"])

    lines = [
        f"**Zampto 服务器报告**",
        f"",
        f"**服务器 ID:** `{report['server_id']}`",
        f"**状态:** {status_icon} {status_cn}",
        f"**操作:** {action_icons.get(report['action'], '❓')} {action_text}",
    ]
    if report.get("expiry"):
        lines.append(f"**到期:** {report['expiry']}")
    if report.get("error"):
        lines.append(f"**错误:** {report['error']}")
    if report.get("action") == "manual_renewal_required":
        lines.extend([
            f"",
            f"**请手动续期**",
            f"API 续期需要人机验证，请在浏览器中打开 Zampto 控制台手动续期。"
        ])
    lines.append(f"")
    lines.append(f"*生成: {report['timestamp']}*")
    body = "\n".join(lines)

    log.info("--- Report ---\n%s", body)
    push_tg("🖥️ Zampto 服务器报告", body)
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(os.path.join(LOG_DIR, "report.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        log.info("Report saved")
    except Exception as e:
        log.warning("Report 保存失败(可忽略): %s", e)


def main():
    # Validate env vars
    if not all([USERNAME, PASSWORD, SERVER_ID]):
        log.error("Missing required env vars: USERNAME, PASSWORD, SERVER_ID")
        push_tg("🚨 Setup Error", "Missing ZAMPTO credentials. Configure GitHub Secrets.")
        return

    log.info("=== Zampto Auto Renewal v5 ===")
    log.info("Server ID: %s | Force: %s", SERVER_ID, FORCE_RENEW)

    # ── Determine mode: GitHub (pure API) or Local (hybrid) ────────
    is_github_actions = bool(os.getenv("GITHUB_ACTION") or os.getenv("CI"))
    session_secret = os.getenv("ZAMPTO_SESSION_SECRET")
    cookies = None

    # Mode A: GitHub Actions – pure API via ZAMPTO_SESSION_SECRET
    if is_github_actions and session_secret:
        log.info("=== GITHUB ACTIONS MODE: Pure API, no browser ===")
        try:
            decoded = base64.b64decode(session_secret).decode("utf-8")
            session_data = json.loads(decoded)
            cookies = session_data.get("cookies", [])
            log.info("Loaded %d cookies from ZAMPTO_SESSION_SECRET", len(cookies))
            if not cookies:
                raise ValueError("No cookies found in session secret")
        except Exception as e:
            log.error("Failed to parse ZAMPTO_SESSION_SECRET: %s", e)
            push_tg("🚨 Session Error", f"Cannot decode ZAMPTO_SESSION_SECRET: {str(e)}")
            cookies = None  # fall through to fail cleanly

    # Mode B: Local dev – try saved session file
    elif not is_github_actions:
        cookies = load_session()
        if cookies:
            log.info("Found session file, using API mode directly")
        else:
            log.info("No session file found - will use interactive login")

    # Mode C: No session available – FAIL
    if not cookies:
        log.error("No valid authentication available - cannot proceed")
        reason = "Missing ZAMPTO_SESSION_SECRET (GitHub) OR missing ./screenshots/session.json (local)"
        push_tg("🚨 Authentication Error", reason)
        report = {
            "server_id": SERVER_ID, "status": "unknown", "action": "none",
            "expiry": None, "error": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _report(report)
        sys.exit(1)  # Non-zero exit so workflow marks as failure

    # 优先: 浏览器续期 (点击 Renew 按钮后由页面 JS 发请求, 自动携带正确 CSRF;
    #        配合 solve_turnstile 处理 Cloudflare 人机验证)
    # 补充: API 模式 (requests 尝试, CSRF 可能失败, 仅作诊断/二次尝试)
    log.info("Starting browser-based renewal (Turnstile-aware)...")
    status = phase_browser_renewal(cookies=cookies)

    # 查询最新到期时间
    expiry_str = ""
    try:
        api = get_api_session()
        sync_cookies_to_session(api, cookies)
        r = api.get(f"{DASHBOARD_URL}/api/servers", timeout=10)
        if r.status_code == 200:
            for sv in (r.json().get("servers") or []):
                if str(sv.get("id")) == str(SERVER_ID):
                    exp_raw = sv.get("renewal", "")
                    if exp_raw:
                        from datetime import datetime as dt_cls, timedelta
                        try:
                            dt_ob = dt_cls.fromisoformat(exp_raw.replace("Z", "+00:00"))
                            expires_at = dt_ob + timedelta(hours=48)
                            now = datetime.now(timezone.utc)
                            if expires_at.tzinfo is None:
                                expires_at = expires_at.replace(tzinfo=timezone.utc)
                            total_s = int((expires_at - now).total_seconds())
                            if total_s > 0:
                                d = total_s // 86400
                                h = (total_s % 86400) // 3600
                                m = (total_s % 3600) // 60
                                parts = []
                                if d > 0: parts.append(f"{d}d")
                                if h > 0: parts.append(f"{h}h")
                                parts.append(f"{m}min")
                                expiry_str = " ".join(parts)
                        except:
                            pass
                    break
    except:
        pass

    if status == "renewed":
        log.info("✓ 续期成功")
        try:
            push_tg("🖥️ Zampto 服务器报告",
                f"**服务器 ID:** `{SERVER_ID}`\n"
                f"**状态:** 🟢 运行中\n"
                f"**操作:** 🔄 已续期"
                + (f"\n**到期:** {expiry_str}" if expiry_str else "") + "\n"
                f"\n*浏览器自动续期完成*")
        except Exception as e:
            log.warning("TG 通知失败(忽略): %s", e)
        # 用 os._exit 替代 sys.exit: sys.exit 触发 SystemExit 异常, 在 Playwright/
        # CloakBrowser 的 event loop 中可能被替换为非 0 退出码导致 workflow 显示失败
        # (续期其实已成功, 仅退出码问题). os._exit 跳过 finalizer, 直接退出 0
        os._exit(0)
    elif status == "skipped":
        log.info("⏭️ 剩余时间充足, 跳过续期")
        try:
            push_tg("🖥️ Zampto 服务器报告",
                f"**服务器 ID:** `{SERVER_ID}`\n"
                f"**状态:** 🟢 运行中\n"
                f"**操作:** ⏭️ 已跳过"
                + (f"\n**到期:** {expiry_str}" if expiry_str else "") + "\n"
                f"\n*剩余时间充足, 无需续期*")
        except Exception as e:
            log.warning("TG 通知失败(忽略): %s", e)
        os._exit(0)

    # 浏览器未成功(failed): 尝试 API 模式 (可能 CSRF 失败, 但值得一试)
    log.info("浏览器续期未成功(%s), 尝试 API 模式...", status)
    api_ok = phase_api_renewal(use_cookies=cookies)
    if api_ok:
        log.info("✅ API 续期流程完成 (报告已通过 API 路径推送)")
        os._exit(0)

    # 两种方式都失败
    log.error("❌ 浏览器和 API 续期均失败")
    try:
        push_tg("🖥️ Zampto 服务器报告",
            f"**服务器 ID:** `{SERVER_ID}`\n"
            f"**状态:** 🔴 失败\n"
            f"**错误:** 浏览器和 API 续期均失败")
    except Exception as e:
        log.warning("TG 通知失败(忽略): %s", e)
    os._exit(1)


if __name__ == "__main__":
    main()
