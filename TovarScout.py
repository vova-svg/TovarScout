from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass
import statistics
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Set
import math
from collections import OrderedDict

def _load_secrets() -> Dict[str, Any]:
    base = os.path.dirname(__file__)
    for name in ('secrets.json', 'secrets.example.json'):
        p = os.path.join(base, name)
        if os.path.isfile(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
    return {}


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
DATA_DIR = os.path.join(ROOT_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)


UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
MAX_SEARCH_ITEMS = 15


if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s %(name)s: %(message)s',
        datefmt='%H:%M:%S'
    )
logger = logging.getLogger('TovarScout')
_LOG_FILE = os.path.join(DATA_DIR, 'tovarscout.log')
try:
    from logging.handlers import RotatingFileHandler
    fh = RotatingFileHandler(_LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding='utf-8')
    fh.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s %(name)s: %(message)s'))
    logging.getLogger().addHandler(fh)
except Exception:
    pass

LAST_RESULTS: Dict[str, Dict[str, Any]] = {}
EMBED_CACHE: Dict[str, List[float]] = {}


HTTP_CACHE: Dict[str, Tuple[float, str]] = {}
CACHE_TTL_DEFAULT = 180.0  # seconds
LAST_HOST_HIT: Dict[str, float] = {}
HOST_MIN_GAP = 0.6  # seconds between requests to same host


@dataclass
class Product:
    url: str
    title: str = ''
    price: Optional[float] = None
    currency: Optional[str] = None
    in_stock: Optional[bool] = None
    rating: Optional[float] = None
    reviews: Optional[int] = None
    sku: Optional[str] = None
    mpn: Optional[str] = None
    gtin: Optional[str] = None  # gtin8/13/14 normalized
    brand: Optional[str] = None
    model: Optional[str] = None
    image: Optional[str] = None


def _num_to_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        try:
            return float(v)
        except Exception:
            return None
    s = str(v)
    s = s.replace('\xa0', ' ').strip()
    s = re.sub(r'[^0-9,\. ]+', '', s)
    s = s.replace(' ', '')
    s = s.replace(',', '.')
    try:
        return float(s)
    except Exception:
        return None


def _http_get(url: str, timeout: int = 20, headers: Optional[Dict[str, str]] = None,
              use_cache: bool = True, ttl: float = CACHE_TTL_DEFAULT,
              use_playwright_fallback: bool = False) -> str:
    if use_cache:
        rec = HTTP_CACHE.get(url)
        if rec and (time.time() - rec[0] < ttl):
            logger.debug('HTTP cache hit: %s (age=%.1fs)', url, time.time() - rec[0])
            return rec[1]

    try:
        host = urllib.parse.urlparse(url).hostname or ''
    except Exception:
        host = ''
    last = LAST_HOST_HIT.get(host, 0.0)
    now = time.time()
    gap = now - last
    if gap < HOST_MIN_GAP:
        sleep_s = HOST_MIN_GAP - gap
        logger.debug('Throttle host %s: sleeping %.2fs', host, sleep_s)
        time.sleep(sleep_s)

    h = {'User-Agent': UA, 'Accept-Language': 'uk,ru;q=0.9,en;q=0.8'}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        logger.debug('HTTP GET %s', url)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
        html = data.decode('utf-8', errors='ignore')
        LAST_HOST_HIT[host] = time.time()
        low = html.lower()
        if use_playwright_fallback and ('captcha' in low or 'cloudflare' in low) and 'application/ld+json' not in low:
            logger.info('Anti-bot detected for %s -> trying browser fallback', url)
            html = _http_get_playwright(url) or html
        logger.debug('HTTP GET ok %s (%d bytes)', url, len(html))
    except urllib.error.HTTPError as e:
        LAST_HOST_HIT[host] = time.time()
        if use_playwright_fallback and e.code in (403, 429):
            logger.warning('HTTP %d for %s -> trying browser fallback', e.code, url)
            html = _http_get_playwright(url) or ''
        else:
            logger.warning('HTTP error %d for %s', e.code, url)
            raise
    except Exception as ex:
        LAST_HOST_HIT[host] = time.time()
        if use_playwright_fallback:
            logger.warning('HTTP GET failed for %s (%s) -> trying browser fallback', url, type(ex).__name__)
            html = _http_get_playwright(url) or ''
        else:
            logger.exception('HTTP GET failed for %s', url)
            raise

    if use_cache and html:
        HTTP_CACHE[url] = (time.time(), html)
    return html


def _http_get_playwright(url: str, wait_css: Optional[str] = None) -> str:
    try:
        try:
            from playwright.sync_api import sync_playwright
            use_patchright = False
        except Exception:
            from patchright.sync_api import sync_playwright  # type: ignore
            use_patchright = True
    except Exception:
        logger.debug('Playwright not available, skipping fallback for %s', url)
        return ''
    try:
        logger.debug('Playwright fetch: %s', url)
        with sync_playwright() as p:
            for headless in (True,):
                try:
                    user_data_dir = os.path.join(DATA_DIR, 'pw_profile')
                    os.makedirs(user_data_dir, exist_ok=True)
                    ctx = p.chromium.launch_persistent_context(
                        user_data_dir=user_data_dir,
                        headless=headless,
                        locale='uk-UA',
                        user_agent=UA,
                        viewport={"width": 1366, "height": 768},
                        args=[
                            '--disable-blink-features=AutomationControlled',
                            '--no-sandbox',
                            '--disable-dev-shm-usage'
                        ]
                    )
                    page = ctx.new_page()
                    try:
                        page.add_init_script("Object.defineProperty(navigator, 'webdriver', { get: () => false });Object.defineProperty(navigator, 'languages', { get: () => ['uk-UA','ru-RU','en-US'] });Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });try { window.chrome = window.chrome || { runtime: {} }; } catch(e) {}")
                    except Exception:
                        pass
                    page.goto(url, timeout=30000, wait_until='domcontentloaded')
                    try:
                        if wait_css:
                            page.wait_for_selector(wait_css, timeout=12000)
                        else:
                            try:
                                page.wait_for_selector('.goods-tile__heading', timeout=8000)
                            except Exception:
                                try:
                                    page.wait_for_selector('a[href*="/p"]', timeout=8000)
                                except Exception:
                                    page.wait_for_load_state('networkidle', timeout=8000)
                    except Exception:
                        pass
                    try:
                        page.evaluate('''(async () => {
                          for (let i=0;i<3;i++) { window.scrollBy(0, window.innerHeight); await new Promise(r=>setTimeout(r, 350)); }
                        })()''')
                    except Exception:
                        pass
                    html = page.content()
                    ctx.close()
                    logger.debug('Playwright ok (headless=%s): %s (%d bytes)', str(headless), url, len(html))
                    return html
                except Exception:
                    try:
                        ctx.close()
                    except Exception:
                        pass
                    raise
    except Exception:
        logger.exception('Playwright fetch failed for %s', url)
        return ''


def _pw_extract_links(url: str, base_url: str, wait_css: Optional[str] = None) -> List[str]:
    try:
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            from patchright.sync_api import sync_playwright  # type: ignore
    except Exception:
        return []
    try:
        with sync_playwright() as p:
            for headless in (True,):
                ctx = None
                try:
                    user_data_dir = os.path.join(DATA_DIR, 'pw_profile')
                    os.makedirs(user_data_dir, exist_ok=True)
                    ctx = p.chromium.launch_persistent_context(
                        user_data_dir=user_data_dir,
                        headless=headless,
                        locale='uk-UA',
                        user_agent=UA,
                        viewport={"width": 1366, "height": 768},
                        args=[
                            '--disable-blink-features=AutomationControlled',
                            '--no-sandbox',
                            '--disable-dev-shm-usage'
                        ]
                    )
                    page = ctx.new_page()
                    page.goto(url, timeout=30000, wait_until='domcontentloaded')
                    try:
                        if wait_css:
                            page.wait_for_selector(wait_css, timeout=10000)
                        else:
                            try:
                                page.wait_for_selector('.goods-tile__heading', timeout=8000)
                            except Exception:
                                page.wait_for_selector('a[href*="/p"]', timeout=8000)
                    except Exception:
                        pass
                    try:
                        page.evaluate('''(async () => {
                          for (let i=0;i<3;i++) { window.scrollBy(0, window.innerHeight); await new Promise(r=>setTimeout(r, 300)); }
                        })()''')
                    except Exception:
                        pass
                    js = (
                        "(() => {\n"
                        " const out = new Set();\n"
                        " const abs = (u) => { try { const a=document.createElement('a'); a.href=u; return a.href; } catch(e){ return u; } };\n"
                        " document.querySelectorAll('a[href*=\"/p\"]').forEach(a => { if (a.href) out.add(abs(a.href)); });\n"
                        " document.querySelectorAll('[data-goods-id],[data-product-id]').forEach(el => {\n"
                        f"   const id = el.getAttribute('data-goods-id') || el.getAttribute('data-product-id'); if (id) out.add('{base_url}/p' + id + '/');\n"
                        " });\n"
                        " return Array.from(out);\n"
                        "})()"
                    )
                    links = page.evaluate(js)
                    ctx.close()
                    out: List[str] = []
                    for u in links or []:
                        uu = str(u).split('#', 1)[0].split('?', 1)[0]
                        if uu.startswith('//'):
                            uu = 'https:' + uu
                        if uu.startswith('/'):
                            uu = base_url + uu
                        out.append(uu)
                    if out:
                        return list(sorted(set(out)))
                except Exception:
                    try:
                        if ctx:
                            ctx.close()
                    except Exception:
                        pass
                    return []
    except Exception:
        return []
    return []


def _extract_itemlist_urls(html: str, base_url: str) -> List[str]:
    urls: Set[str] = set()
    try:
        blocks = re.findall(r'<script[^>]+type=("|")application/ld\+json\1[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        for _, block in blocks:
            try:
                data = json.loads(block.strip())
            except Exception:
                continue
            items: List[Dict[str, Any]] = []
            if isinstance(data, dict):
                data = [data]
            if isinstance(data, list):
                for node in data:
                    if not isinstance(node, dict):
                        continue
                    if str(node.get('@type') or '').lower() == 'itemlist' and node.get('itemListElement'):
                        try:
                            for el in node.get('itemListElement') or []:
                                if isinstance(el, dict):
                                    url = None
                                    if isinstance(el.get('item'), dict):
                                        url = el['item'].get('@id') or el['item'].get('url')
                                    url = url or el.get('url')
                                    if url:
                                        u = str(url).split('#', 1)[0].split('?', 1)[0]
                                        if u.startswith('//'):
                                            u = 'https:' + u
                                        if u.startswith('/'):
                                            u = base_url + u
                                        if u.startswith('http'):
                                            urls.add(u)
                        except Exception:
                            continue
    except Exception:
        return []
    return list(urls)


class Provider:
    name: str = 'base'
    base_url: str = ''

    def search(self, query: str, max_pages: int = 1, delay_sec: float = 0.8) -> List[Product]:
        raise NotImplementedError


def _provider_map(include_rozetka: bool = False) -> Dict[str, Provider]:
    provs: Dict[str, Provider] = {
        'comfy': ComfyProvider(),
        'prom': PromProvider(),
        'allo': AlloProvider(),
        'foxtrot': FoxtrotProvider(),
        'eldorado': EldoradoProvider(),
    'web': WebSearchProvider(),
    }
    return provs


def _title_key(s: str) -> str:
    t = (s or '').lower()
    t = re.sub(r'[^a-z0-9а-яёіїєґ ]+', ' ', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t


def _score_product(p: Product) -> float:
    import math
    rv = max(1, (p.reviews or 0))
    rat = p.rating or 0
    pr = (p.price or 0) or 1
    return (rat * math.log(1 + rv)) / pr


def _wilson_lower_bound(rating: Optional[float], reviews: Optional[int]) -> float:
    try:
        if rating is None or (reviews or 0) <= 0:
            return 0.0
        r = max(0.0, min(5.0, float(rating))) / 5.0
        n = max(0, int(reviews))
        if n == 0:
            return 0.0
        from math import sqrt
        z = 1.96  # 95%
        phat = r
        denom = 1 + z*z/n
        num = phat + z*z/(2*n) - z*sqrt((phat*(1-phat) + z*z/(4*n))/n)
        return max(0.0, num/denom)
    except Exception:
        return 0.0


def _canonical_key(p: Product) -> str:
    if p.gtin:
        return f"gtin:{str(p.gtin).strip()}"
    if p.mpn and p.brand:
        return f"mpn:{str(p.brand).lower().strip()}|{str(p.mpn).lower().strip()}"
    if p.mpn:
        return f"mpn:{str(p.mpn).lower().strip()}"
    if p.sku and p.brand:
        return f"sku:{str(p.brand).lower().strip()}|{str(p.sku).lower().strip()}"
    if p.brand and p.model:
        return f"bm:{str(p.brand).lower().strip()}|{str(p.model).lower().strip()}"
    try:
        host = urllib.parse.urlparse(p.url).hostname or ''
    except Exception:
        host = ''
    return host + '|' + _title_key(p.title)


def _infer_brand_model(p: Product) -> None:
    title = _title_key(p.title)
    if not title:
        return
    brands = [
        'apple','samsung','xiaomi','redmi','mi','oneplus','oppo','vivo','realme','huawei','honor','nokia',
        'sony','playstation','ps5','ps4','microsoft','xbox','lenovo','hp','dell','acer','asus','msi','gigabyte',
        'logitech','razer','steelseries','canon','nikon','panasonic','philips','tcl','hisense','lg'
    ]
    if not p.brand:
        for b in brands:
            if re.search(r'\b' + re.escape(b) + r'\b', title):
                p.brand = b
                break
    if not p.model:
        toks = [t for t in re.split(r'[^a-z0-9+_-]+', title) if t]
        stop = set(['ultra','pro','max','mini','smart','tv','laptop','notebook','phone','Телефон','смартфон'])
        cand = [t for t in toks if any(c.isdigit() for c in t) and not t in stop and 2 < len(t) < 16]
        if p.brand:
            try:
                i = toks.index(p.brand)
                if i+1 < len(toks) and toks[i+1] in cand:
                    p.model = toks[i+1]
            except Exception:
                pass
        if not p.model and cand:
            p.model = cand[0]


def _parse_microdata_rdfa_into(html: str, p: Product) -> None:
    m = re.search(r'<[^>]+itemscope[^>]+itemtype=["\"][^"\"]*schema.org/(Product|IndividualProduct)["\"][^>]*>(.*?)</', html, re.IGNORECASE | re.DOTALL)
    if m:
        block = m.group(0)
        def attr(name: str) -> Optional[str]:
            mm = re.search(r'itemprop=["\"]' + re.escape(name) + r'["\"][^>]*(?:content=["\"]([^"\"]+)["\"])?', block, re.IGNORECASE)
            if mm and mm.group(1):
                return mm.group(1)
            mm2 = re.search(r'itemprop=["\"]' + re.escape(name) + r'["\"][^>]*>([^<]+)<', block, re.IGNORECASE)
            return mm2.group(1).strip() if mm2 else None
        p.title = p.title or (attr('name') or '')
        p.brand = p.brand or attr('brand')
        p.sku = p.sku or attr('sku')
        p.mpn = p.mpn or attr('mpn')
        if not p.gtin:
            for key in ('gtin','gtin8','gtin12','gtin13','gtin14'):
                v = attr(key)
                if v:
                    p.gtin = v
                    break
        price = attr('price')
        if p.price is None and price:
            p.price = _num_to_float(price)
        if not p.currency:
            p.currency = attr('priceCurrency') or p.currency
        av = attr('availability')
        if av and p.in_stock is None:
            low = av.lower()
            p.in_stock = any(k in low for k in ['instock','in_stock','available'])
        if not p.image:
            p.image = attr('image') or p.image
    if not p.title:
        mm = re.search(r'property=["\"]schema:name["\"][^>]*content=["\"]([^"\"]+)["\"]', html, re.IGNORECASE)
        if mm:
            p.title = mm.group(1)
    if p.price is None:
        mm = re.search(r'property=["\"]schema:price["\"][^>]*content=["\"]([^"\"]+)["\"]', html, re.IGNORECASE)
        if mm:
            p.price = _num_to_float(mm.group(1))
    if not p.currency:
        mm = re.search(r'property=["\"]schema:priceCurrency["\"][^>]*content=["\"]([^"\"]+)["\"]', html, re.IGNORECASE)
        if mm:
            p.currency = mm.group(1)
    if p.in_stock is None:
        mm = re.search(r'property=["\"]schema:availability["\"][^>]*content=["\"]([^"\"]+)["\"]', html, re.IGNORECASE)
        if mm:
            low = mm.group(1).lower()
            p.in_stock = any(k in low for k in ['instock','in_stock','available'])
    if not p.image:
        mm = re.search(r'property=["\"]og:image["\"][^>]*content=["\"]([^"\"]+)["\"]', html, re.IGNORECASE)
        if mm:
            p.image = mm.group(1)


def _embedding(text: str) -> List[float]:
    key = _title_key(text)
    if key in EMBED_CACHE:
        return EMBED_CACHE[key]
    dim = 64
    vec = [0.0] * dim
    t = key
    for i in range(len(t)):
        for L in (2, 3, 4):
            if i + L <= len(t):
                n = t[i:i+L]
                h = (hash(n) & 0x7fffffff) % dim
                vec[h] += 1.0
    norm = math.sqrt(sum(v*v for v in vec)) or 1.0
    vec = [v / norm for v in vec]
    EMBED_CACHE[key] = vec
    return vec


def _embedding_similarity(a: str, b: str) -> float:
    va = _embedding(a)
    vb = _embedding(b)
    s = sum(x*y for x, y in zip(va, vb))
    return max(0.0, min(1.0, (s + 1.0) / 2.0))


def _relevance_score(query: str, title: str) -> float:
    use_emb = os.getenv('USE_EMBEDDINGS') == '1'
    if use_emb:
        try:
            return _embedding_similarity(query, title)
        except Exception:
            pass
    qt = set(_normalize_query_tokens(query))
    tt = set(_normalize_query_tokens(title))
    if not qt or not tt:
        return 0.0
    inter = len(qt & tt)
    base = max(1, min(len(qt), len(tt)))
    return inter / base


def _normalize_query_tokens(text: str) -> List[str]:
    t = _title_key(text)
    toks = t.split()
    out: Set[str] = set(toks)
    syn = {
        'нашники': ['наушники'],
    'наушнеи': ['наушники'],
    'наушн': ['наушники'],
        'наушник': ['наушники'],
        'аирподс': ['airpods'],
        'эйрподс': ['airpods'],
        'ейрподс': ['airpods'],
        'айрподс': ['airpods'],
        'наушники': ['earbuds', 'headphones', 'гарнитура'],
        'гарнитура': ['наушники', 'headset'],
    'амбушур': ['амбушюры','earpads','ear tips','earhooks'],
        'чехол': ['case', 'cover', 'кейс'],
        'кейс': ['чехол', 'case'],
        'apple': ['эппл', 'эпл'],
        'эппл': ['apple'],
        'эпл': ['apple'],
    }
    for tok in list(out):
        if tok in syn:
            for x in syn[tok]:
                out.add(x)
    return list(out)


def _is_accessory(title: str) -> bool:
    t = _title_key(title)
    cfg = os.getenv('ACCESSORY_BLOCKLIST') or ''
    if cfg:
        keys = [k.strip().lower() for k in cfg.split(',') if k.strip()]
    else:
        keys = [
            'чехол','кейс','case','cover','накладк','брелок','подвеска','стекло','пленка','кабель','переходник',
            'адаптер','зарядк','зарядное','adapter','charger','подставк','держател','ремешок','браслет','стикер','наклейк',
            'картридер','карта памяти','sd ','microsd','micro sd','флешк','usbhub','usb hub','хаб','док-станц','док станц',
            'брекет','фильтр экрана','glass','tempered','пленк','чехол-книж','sleeve','рукав','сумка','кейc','car holder',
            'кейкап','keycap','keycaps','свитч ','свитчи','switch ','switches','пружин','стабилизатор','стабилизаторы','стабы','смазк','lub','lubricant',
            'амбушур','амбушюры','earpads','ear tips','earhooks','оголовье','ear cushions','ear pads','для naushnik','для наушник','кейc airpods','чехол airpods'
        ]
    return any(k in t for k in keys)


def _wants_accessory(query: str) -> bool:
    t = _title_key(query)
    return any(k in t for k in ['чехол', 'кейс', 'case', 'cover'])


def _filters_help() -> str:
    cur = os.getenv('ACCESSORY_BLOCKLIST') or '(по умолчанию) чехол, кейс, cover, накладк, брелок, подвеска, стекло, пленка, кабель, переходник'
    return (
        "Фильтры аксессуаров:\n"
        f"ACCESSORY_BLOCKLIST: {cur}\n"
        "Команды:\n"
        "/filters show — показать текущие\n"
        "/filters set <csv> — установить (через запятую)\n"
        "/filters reset — вернуть по умолчанию"
    )


class RozetkaProvider(Provider):
    name = 'rozetka'
    base_url = 'https://rozetka.com.ua'

    def _search_page(self, query: str, page: int = 1) -> List[str]:
        q = urllib.parse.quote(query)
        url = f"{self.base_url}/ua/search/?text={q}&page={page}"
        logger.debug('[rozetka] search page %s', url)
        html = _http_get(url, timeout=25, use_playwright_fallback=False)

        links: Set[str] = set()
        for m in re.finditer(r'href=\"(https?://[^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html):
            links.add(m.group(1))
        for m in re.finditer(r'href=\"(/[^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html):
            links.add(self.base_url + m.group(1))
        for m in re.finditer(r'href=\"//([^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html):
            links.add('https://' + m.group(1))
        for m in re.finditer(r'<a[^>]+class=\"[^\"]*goods-tile__heading[^\"]*\"[^>]+href=\"([^\"]+)\"', html, re.IGNORECASE):
            href = m.group(1)
            if href.startswith('http'):
                links.add(href)
            else:
                links.add(self.base_url + href)
        for m in re.finditer(r'data-url=\"(/[^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html, re.IGNORECASE):
            links.add(self.base_url + m.group(1))
        for m in re.finditer(r'data-(goods-id|product-id)=\"(\d{5,})\"', html, re.IGNORECASE):
            gid = m.group(2)
            links.add(f"{self.base_url}/p{gid}/")
        for m in re.finditer(r'\"product_id\"\s*:\s*\"?(\d{5,})\"?', html):
            gid = m.group(1)
            links.add(f"{self.base_url}/p{gid}/")
        for m in re.finditer(r'\"goods_id\"\s*:\s*\"?(\d{5,})\"?', html):
            gid = m.group(1)
            links.add(f"{self.base_url}/p{gid}/")
        for m in re.finditer(r'\"id\"\s*:\s*(\d{5,})', html):
            gid = m.group(1)
            links.add(f"{self.base_url}/p{gid}/")
        for m in re.finditer(r'(["\'])((?:/|https?://)[^"\']*?/p\d{5,}[^"\']*)(["\'])', html):
            href = m.group(2)
            if href.startswith('http'):
                links.add(href)
            else:
                links.add(self.base_url + href)

        if not links:
            low = html.lower()
            if ('captcha' in low or 'cloudflare' in low or 'checking your browser' in low or 'please turn' in low) or ('goods-tile' not in low):
                logger.info('[rozetka] listing likely blocked, retrying with browser fallback')
                html2 = _http_get_playwright(url, wait_css='.goods-tile__heading')
                if html2:
                    html = html2
                    for m in re.finditer(r'href=\"(https?://[^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html):
                        links.add(m.group(1))
                    for m in re.finditer(r'href=\"(/[^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html):
                        links.add(self.base_url + m.group(1))
                    for m in re.finditer(r'href=\"//([^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html):
                        links.add('https://' + m.group(1))
                    for m in re.finditer(r'<a[^>]+class=\"[^\"]*goods-tile__heading[^\"]*\"[^>]+href=\"([^\"]+)\"', html, re.IGNORECASE):
                        href = m.group(1)
                        if href.startswith('http'):
                            links.add(href)
                        else:
                            links.add(self.base_url + href)
                    for m in re.finditer(r'data-url=\"(/[^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html, re.IGNORECASE):
                        links.add(self.base_url + m.group(1))
                    for m in re.finditer(r'data-(goods-id|product-id)=\"(\d{5,})\"', html, re.IGNORECASE):
                        gid = m.group(2)
                        links.add(f"{self.base_url}/p{gid}/")
                    for m in re.finditer(r'\"product_id\"\s*:\s*\"?(\d{5,})\"?', html):
                        gid = m.group(1)
                        links.add(f"{self.base_url}/p{gid}/")

        if not links:
            url_alt = f"{self.base_url}/search/?text={q}&page={page}"
            try:
                logger.info('[rozetka] retrying alt search URL')
                html_alt = _http_get(url_alt, timeout=25, use_playwright_fallback=False)
            except Exception:
                html_alt = ''
            if not html_alt:
                html_alt = _http_get_playwright(url_alt, wait_css='.goods-tile__heading')
            if html_alt:
                html = html_alt
                for m in re.finditer(r'href=\"(https?://[^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html):
                    links.add(m.group(1))
                for m in re.finditer(r'href=\"(/[^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html):
                    links.add(self.base_url + m.group(1))
                for m in re.finditer(r'href=\"//([^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html):
                    links.add('https://' + m.group(1))
                for m in re.finditer(r'<a[^>]+class=\"[^\"]*goods-tile__heading[^\"]*\"[^>]+href=\"([^\"]+)\"', html, re.IGNORECASE):
                    href = m.group(1)
                    if href.startswith('http'):
                        links.add(href)
                    else:
                        links.add(self.base_url + href)
                for m in re.finditer(r'data-url=\"(/[^\"\s>]+?/p\d{5,}[^\"\s>]*)\"', html, re.IGNORECASE):
                    links.add(self.base_url + m.group(1))
                for m in re.finditer(r'data-(goods-id|product-id)=\"(\d{5,})\"', html, re.IGNORECASE):
                    gid = m.group(2)
                    links.add(f"{self.base_url}/p{gid}/")
                for m in re.finditer(r'\"product_id\"\s*:\s*\"?(\d{5,})\"?', html):
                    gid = m.group(1)
                    links.add(f"{self.base_url}/p{gid}/")

        if not links:
            dom_links = _pw_extract_links(url, self.base_url, wait_css='.goods-tile__heading')
            if not dom_links:
                dom_links = _pw_extract_links(f"{self.base_url}/search/?text={q}&page={page}", self.base_url, wait_css='.goods-tile__heading')
            for u in dom_links:
                links.add(u)

        if links:
            norm: Set[str] = set()
            for u in links:
                uu = u.split('#', 1)[0]
                uu = uu.split('?', 1)[0]
                if uu.startswith('//'):
                    uu = 'https:' + uu
                if uu.startswith('/'):
                    uu = self.base_url + uu
                norm.add(uu)
            links = norm

        logger.info('[rozetka] links found: %d (page %d)', len(links), page)
        if not links:
            try:
                dump_dir = os.path.join(DATA_DIR, 'diagnostics')
                os.makedirs(dump_dir, exist_ok=True)
                fp = os.path.join(dump_dir, f'rozetka_search_{int(time.time())}_p{page}.html')
                with open(fp, 'w', encoding='utf-8') as f:
                    f.write(html)
                logger.info('[rozetka] saved HTML snapshot: %s', fp)
            except Exception:
                pass
        return list(links)

    def search(self, query: str, max_pages: int = 1, delay_sec: float = 0.8) -> List[Product]:
        logger.info('[rozetka] search: "%s" pages=%d', query, max_pages)
        urls: List[str] = []
        for p in range(1, max(1, int(max_pages)) + 1):
            try:
                urls.extend(self._search_page(query, p))
            except Exception:
                logger.exception('[rozetka] search page failed p=%d', p)
                break
            time.sleep(delay_sec)
        seen = set()
        out: List[Product] = []
        for u in urls:
            if u in seen:
                continue
            seen.add(u)
            try:
                out.append(fetch_product(u))
            except Exception:
                logger.exception('[rozetka] fetch failed: %s', u)
                continue
            time.sleep(0.6)
            if len(out) >= MAX_SEARCH_ITEMS:
                break
        logger.info('[rozetka] products parsed: %d', len(out))
        return out


class ComfyProvider(Provider):
    name = 'comfy'
    base_url = 'https://comfy.ua'

    def _search_page(self, query: str, page: int = 1) -> List[str]:
        q = urllib.parse.quote(query)
        urls_try = [
            f"{self.base_url}/ua/search/?q={q}&p={page}",
            f"{self.base_url}/ua/catalogsearch/result/?q={q}&p={page}"
        ]
        links = set()
        for su in urls_try:
            try:
                logger.debug('[comfy] search page %s', su)
                html = _http_get(su, timeout=25, use_playwright_fallback=False)
            except Exception:
                continue
            for m in re.finditer(r'href=\"(https?://[^\"\s]+?\.html)\"', html):
                links.add(m.group(1))
            for m in re.finditer(r'href=\"(/[^\"\s]+?\.html)\"', html):
                links.add(self.base_url + m.group(1))
            for m in re.finditer(r'<a[^>]+class=\"[^\"]*(product-card|product__heading)[^\"]*\"[^>]+href=\"([^\"]+\.html)\"', html, re.IGNORECASE):
                href = m.group(2)
                if href.startswith('http'):
                    links.add(href)
                else:
                    links.add(self.base_url + href)
            for m in re.finditer(r'data-(product-url|url)=\"([^\"]+\.html)\"', html, re.IGNORECASE):
                href = m.group(2)
                if href.startswith('http'):
                    links.add(href)
                else:
                    links.add(self.base_url + href)
            if links:
                break
        logger.debug('[comfy] links found: %d (page %d)', len(links), page)
        return list(links)

    def search(self, query: str, max_pages: int = 1, delay_sec: float = 0.8) -> List[Product]:
        logger.info('[comfy] search: "%s" pages=%d', query, max_pages)
        urls: List[str] = []
        for p in range(1, max(1, int(max_pages)) + 1):
            try:
                urls.extend(self._search_page(query, p))
            except Exception:
                logger.exception('[comfy] search page failed p=%d', p)
                break
            time.sleep(delay_sec)
        seen = set()
        out: List[Product] = []
        for u in urls:
            if u in seen:
                continue
            seen.add(u)
            try:
                out.append(fetch_product(u))
            except Exception:
                logger.exception('[comfy] fetch failed: %s', u)
                continue
            time.sleep(0.6)
            if len(out) >= MAX_SEARCH_ITEMS:
                break
        logger.info('[comfy] products parsed: %d', len(out))
        return out


class PromProvider(Provider):
    name = 'prom'
    base_url = 'https://prom.ua'

    def _search_page(self, query: str, page: int = 1) -> List[str]:
        q = urllib.parse.quote(query)
        url = f"{self.base_url}/ua/search?search_term={q}&page={page}"
        logger.debug('[prom] search page %s', url)
        html = _http_get(url, timeout=25, use_playwright_fallback=False)
        links = set()
        for m in re.finditer(r'href=\"(https?://[^\"\s]+?/p\d+[^\"\s/]*)\"', html):
            links.add(m.group(1))
        for m in re.finditer(r'href=\"(/p\d+[^\"\s/]*)\"', html):
            links.add(self.base_url + m.group(1))
        logger.debug('[prom] links found: %d (page %d)', len(links), page)
        return list(links)

    def search(self, query: str, max_pages: int = 1, delay_sec: float = 0.8) -> List[Product]:
        logger.info('[prom] search: "%s" pages=%d', query, max_pages)
        urls: List[str] = []
        for p in range(1, max(1, int(max_pages)) + 1):
            try:
                urls.extend(self._search_page(query, p))
            except Exception:
                logger.exception('[prom] search page failed p=%d', p)
                break
            time.sleep(delay_sec)
        seen = set()
        out: List[Product] = []
        for u in urls:
            if u in seen:
                continue
            seen.add(u)
            try:
                out.append(fetch_product(u))
            except Exception:
                logger.exception('[prom] fetch failed: %s', u)
                continue
            time.sleep(0.6)
            if len(out) >= MAX_SEARCH_ITEMS:
                break
        logger.info('[prom] products parsed: %d', len(out))
        return out


class AlloProvider(Provider):
    name = 'allo'
    base_url = 'https://allo.ua'

    def _search_page(self, query: str, page: int = 1) -> List[str]:
        q = urllib.parse.quote(query)
        urls_try = [
            f"{self.base_url}/ua/catalogsearch/result/?q={q}&p={page}",
            f"{self.base_url}/ru/catalogsearch/result/?q={q}&p={page}",
        ]
        links: Set[str] = set()
        for su in urls_try:
            try:
                logger.debug('[allo] search page %s', su)
                html = _http_get(su, timeout=25, use_playwright_fallback=False)
            except Exception:
                continue
            for u in _extract_itemlist_urls(html, self.base_url):
                if u.endswith('.html'):
                    links.add(u)
            for m in re.finditer(r'href=\"(https?://[^\"\s]+?\.html)\"', html):
                if 'allo.ua' in m.group(1):
                    links.add(m.group(1))
            for m in re.finditer(r'href=\"(/[^\"\s]+?\.html)\"', html):
                links.add(self.base_url + m.group(1))
            if links:
                break
        logger.debug('[allo] links found: %d (page %d)', len(links), page)
        return list(links)

    def search(self, query: str, max_pages: int = 1, delay_sec: float = 0.8) -> List[Product]:
        logger.info('[allo] search: "%s" pages=%d', query, max_pages)
        urls: List[str] = []
        for p in range(1, max(1, int(max_pages)) + 1):
            try:
                urls.extend(self._search_page(query, p))
            except Exception:
                logger.exception('[allo] search page failed p=%d', p)
                break
            time.sleep(delay_sec)
        seen = set()
        out: List[Product] = []
        for u in urls:
            if u in seen:
                continue
            seen.add(u)
            try:
                out.append(fetch_product(u))
            except Exception:
                logger.exception('[allo] fetch failed: %s', u)
                continue
            time.sleep(0.6)
            if len(out) >= MAX_SEARCH_ITEMS:
                break
        logger.info('[allo] products parsed: %d', len(out))
        return out


class FoxtrotProvider(Provider):
    name = 'foxtrot'
    base_url = 'https://www.foxtrot.com.ua'

    def _search_page(self, query: str, page: int = 1) -> List[str]:
        q = urllib.parse.quote(query)
        urls_try = [
            f"{self.base_url}/uk/search?query={q}&page={page}",
            f"{self.base_url}/ru/search?query={q}&page={page}",
        ]
        links: Set[str] = set()
        for su in urls_try:
            try:
                logger.debug('[foxtrot] search page %s', su)
                html = _http_get(su, timeout=25, use_playwright_fallback=False)
            except Exception:
                continue
            for u in _extract_itemlist_urls(html, self.base_url):
                if 'foxtrot.com.ua' in u:
                    links.add(u)
            for m in re.finditer(r'href=\"(https?://[^\"\s]+/(uk|ru)/product/[^\"\s]+)\"', html):
                links.add(m.group(1).split('?')[0])
            for m in re.finditer(r'href=\"(/(uk|ru)/product/[^\"\s]+)\"', html):
                links.add(self.base_url + m.group(1))
            if links:
                break
        logger.debug('[foxtrot] links found: %d (page %d)', len(links), page)
        return list(links)

    def search(self, query: str, max_pages: int = 1, delay_sec: float = 0.8) -> List[Product]:
        logger.info('[foxtrot] search: "%s" pages=%d', query, max_pages)
        urls: List[str] = []
        for p in range(1, max(1, int(max_pages)) + 1):
            try:
                urls.extend(self._search_page(query, p))
            except Exception:
                logger.exception('[foxtrot] search page failed p=%d', p)
                break
            time.sleep(delay_sec)
        seen = set()
        out: List[Product] = []
        for u in urls:
            if u in seen:
                continue
            seen.add(u)
            try:
                out.append(fetch_product(u))
            except Exception:
                logger.exception('[foxtrot] fetch failed: %s', u)
                continue
            time.sleep(0.6)
            if len(out) >= MAX_SEARCH_ITEMS:
                break
        logger.info('[foxtrot] products parsed: %d', len(out))
        return out


class EldoradoProvider(Provider):
    name = 'eldorado'
    base_url = 'https://eldorado.ua'

    def _search_page(self, query: str, page: int = 1) -> List[str]:
        q = urllib.parse.quote(query)
        urls_try = [
            f"{self.base_url}/uk/search/?q={q}&p={page}",
            f"{self.base_url}/ru/search/?q={q}&p={page}",
            f"{self.base_url}/uk/catalogsearch/result/?q={q}&p={page}",
        ]
        links: Set[str] = set()
        for su in urls_try:
            try:
                logger.debug('[eldorado] search page %s', su)
                html = _http_get(su, timeout=25, use_playwright_fallback=False)
            except Exception:
                continue
            for u in _extract_itemlist_urls(html, self.base_url):
                if 'eldorado.ua' in u:
                    links.add(u)
            for m in re.finditer(r'href=\"(https?://[^\"\s]+/(product|goods)/[^\"\s]+)\"', html, re.IGNORECASE):
                if 'eldorado.ua' in m.group(1):
                    links.add(m.group(1).split('?')[0])
            for m in re.finditer(r'href=\"(/[^\"\s]+?\.html)\"', html, re.IGNORECASE):
                links.add(self.base_url + m.group(1))
            if links:
                break
        logger.debug('[eldorado] links found: %d (page %d)', len(links), page)
        return list(links)

    def search(self, query: str, max_pages: int = 1, delay_sec: float = 0.8) -> List[Product]:
        logger.info('[eldorado] search: "%s" pages=%d', query, max_pages)
        urls: List[str] = []
        for p in range(1, max(1, int(max_pages)) + 1):
            try:
                urls.extend(self._search_page(query, p))
            except Exception:
                logger.exception('[eldorado] search page failed p=%d', p)
                break
            time.sleep(delay_sec)
        seen = set()
        out: List[Product] = []
        for u in urls:
            if u in seen:
                continue
            seen.add(u)
            try:
                out.append(fetch_product(u))
            except Exception:
                logger.exception('[eldorado] fetch failed: %s', u)
                continue
            time.sleep(0.6)
            if len(out) >= MAX_SEARCH_ITEMS:
                break
        logger.info('[eldorado] products parsed: %d', len(out))
        return out


class WebSearchProvider(Provider):
    name = 'web'
    base_url = 'https://duckduckgo.com/'

    def search(self, query: str, max_pages: int = 1, delay_sec: float = 0.8) -> List[Product]:
        items: List[Product] = []
        q = urllib.parse.quote_plus(query + ' купить цена site:.ua')
        for page in range(1, max_pages + 1):
            try:
                url = f"https://duckduckgo.com/html/?q={q}&s={(page-1)*50}"
                html = _http_get(url, headers={'User-Agent': UA, 'Accept-Language': 'ru,en;q=0.9'})
            except Exception:
                logger.warning('[web] ddg failed for %s page=%d', query, page)
                break
            urls: List[str] = []
            try:
                for m in re.finditer(r'href=\"(https?://[^\"]+)\"', html):
                    u = urllib.parse.unquote(m.group(1))
                    if 'duckduckgo.com' in u:
                        continue
                    if u.startswith('http'):
                        urls.append(u)
            except Exception:
                pass
            seen: Set[str] = set()
            for u in urls:
                host = urllib.parse.urlparse(u).hostname or ''
                if not host or 'duckduckgo.com' in host:
                    continue
                if host in seen:
                    continue
                seen.add(host)
                try:
                    items.append(fetch_product(u))
                except Exception:
                    continue
                time.sleep(0.6)
            if not urls:
                break
        return [p for p in items if p and (p.price is not None or p.in_stock is not None) and p.title]


def _parse_json_ld(html: str) -> Dict[str, Any]:
    m = re.search(r'<script[^>]+type=("|")application/ld\+json\1[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
    if not m:
        blocks = re.findall(r'<script[^>]+type=("|")application/ld\+json\1[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        for _, block in blocks:
            try:
                data = json.loads(block.strip())
            except Exception:
                continue
            if isinstance(data, dict) and ('@type' in data) and ('Offer' in json.dumps(data)):
                return data
        return {}
    try:
        return json.loads(m.group(2).strip())
    except Exception:
        return {}


def fetch_product(url: str) -> Product:
    logger.debug('fetch_product: %s', url)
    def _strip_track(u: str) -> str:
        try:
            pr = urllib.parse.urlparse(u)
            q = urllib.parse.parse_qsl(pr.query, keep_blank_values=True)
            bad = {'utm_source','utm_medium','utm_campaign','utm_term','utm_content','gclid','yclid','fbclid','utm_referrer'}
            q2 = [(k,v) for (k,v) in q if k.lower() not in bad]
            pr2 = pr._replace(query=urllib.parse.urlencode(q2))
            return urllib.parse.urlunparse(pr2)
        except Exception:
            return u
    url = _strip_track(url)
    html = _http_get(url, timeout=25)
    mcanon = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if mcanon:
        try:
            url = _strip_track(urllib.parse.urljoin(url, mcanon.group(1)))
        except Exception:
            pass
    data = _parse_json_ld(html)
    p = Product(url=url)
    def _dig(obj):
        if isinstance(obj, dict):
            return [obj]
        if isinstance(obj, list):
            return obj
        return []
    nodes = _dig(data)
    prod_nodes = [n for n in nodes if isinstance(n, dict) and n.get('@type') in ('Product', 'IndividualProduct')]
    if prod_nodes:
        node = prod_nodes[0]
        p.title = str(node.get('name') or '')
        p.brand = (node.get('brand') or {}).get('name') if isinstance(node.get('brand'), dict) else (str(node.get('brand')) if node.get('brand') else None)
        p.sku = str(node.get('sku')) if node.get('sku') is not None else None
        p.mpn = str(node.get('mpn')) if node.get('mpn') is not None else None
        for key in ('gtin', 'gtin8', 'gtin12', 'gtin13', 'gtin14'):
            if node.get(key):
                p.gtin = str(node.get(key))
                break
        if node.get('model'):
            p.model = node['model'].get('name') if isinstance(node['model'], dict) else str(node['model'])
        offers = node.get('offers')
        if isinstance(offers, dict):
            if offers.get('@type') == 'AggregateOffer':
                low = _num_to_float(offers.get('lowPrice'))
                high = _num_to_float(offers.get('highPrice'))
                p.price = low or high or _num_to_float(offers.get('price'))
                p.currency = offers.get('priceCurrency')
            else:
                p.price = _num_to_float(offers.get('price'))
                p.currency = offers.get('priceCurrency')
            av = str(offers.get('availability') or '').lower()
            p.in_stock = any(k in av for k in ['instock', 'in_stock', 'in stock', 'available'])
        elif isinstance(offers, list):
            prices: List[float] = []
            cur = None
            for of in offers:
                if not isinstance(of, dict):
                    continue
                pr = _num_to_float(of.get('price'))
                if pr is not None:
                    prices.append(pr)
                    if not cur:
                        cur = of.get('priceCurrency')
            if prices:
                p.price = min(prices)
                p.currency = cur
        agg = node.get('aggregateRating') or {}
        try:
            p.rating = float(agg.get('ratingValue')) if agg.get('ratingValue') is not None else None
        except Exception:
            p.rating = None
        try:
            p.reviews = int(agg.get('reviewCount')) if agg.get('reviewCount') is not None else None
        except Exception:
            p.reviews = None
        img = node.get('image')
        if isinstance(img, list) and img:
            p.image = str(img[0])
        elif isinstance(img, str):
            p.image = img
    else:
        _parse_microdata_rdfa_into(html, p)
        if p.price is None:
            m = re.search(r'"price"\s*:\s*"?([\d\s.,]+)', html)
            if m:
                p.price = _num_to_float(m.group(1))
        if p.price is None:
            m2 = re.search(r'itemprop=\"price\"[^>]*content=\"([\d\s.,]+)\"', html)
            if m2:
                p.price = _num_to_float(m2.group(1))
        if p.price is None:
            m3 = re.search(r'class=\"[^\"]*(price|money)[^\"]*\"[^>]*>([\d\s.,]+)<', html, re.IGNORECASE)
            if m3:
                p.price = _num_to_float(m3.group(2))
        if not p.currency:
            if re.search(r'₴|грн', html, re.IGNORECASE):
                p.currency = 'UAH'
            elif re.search(r'\$', html):
                p.currency = 'USD'
        low = html.lower()
        if p.in_stock is None:
            p.in_stock = any(k in low for k in ['in_stock', 'instock', 'в наявності', 'в наличии', 'доступно', 'available'])
        if not p.title:
            t_ = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if t_:
                p.title = re.sub(r'\s+', ' ', t_.group(1)).strip()
        if not p.image:
            mimg = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if mimg:
                p.image = mimg.group(1)
    _infer_brand_model(p)
    logger.debug('parsed product: title="%s" price=%s %s rating=%s reviews=%s stock=%s',
                 (p.title or '')[:60], str(p.price), p.currency or '', str(p.rating), str(p.reviews), str(p.in_stock))
    return p


class RZStorage:
    def __init__(self, db_path: Optional[str] = None):
        if not db_path:
            db_path = os.path.join(DATA_DIR, 'bot.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init()

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def _init(self):
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(
                'CREATE TABLE IF NOT EXISTS rz_watches ('
                ' id INTEGER PRIMARY KEY AUTOINCREMENT,'
                ' chat_id TEXT NOT NULL,'
                ' url TEXT NOT NULL,'
                ' title TEXT,'
                ' target_price REAL,'
                ' notify_stock INTEGER DEFAULT 1,'
                ' notify_drop INTEGER DEFAULT 1,'
                ' last_price REAL,'
                ' last_stock INTEGER,'
                ' created_at TEXT,'
                ' updated_at TEXT'
                ')'
            )
            cur.execute('CREATE INDEX IF NOT EXISTS idx_rz_watches_chat ON rz_watches(chat_id)')
            cur.execute('CREATE UNIQUE INDEX IF NOT EXISTS uq_rz_watch ON rz_watches(chat_id, url)')
            cur.execute(
                'CREATE TABLE IF NOT EXISTS ts_query_watches ('
                ' id INTEGER PRIMARY KEY AUTOINCREMENT,'
                ' chat_id TEXT NOT NULL,'
                ' provider TEXT NOT NULL,'
                ' query TEXT NOT NULL,'
                ' max_price REAL,'
                ' min_rating REAL,'
                ' created_at TEXT,'
                ' updated_at TEXT,'
                ' UNIQUE(chat_id, provider, query)'
                ')'
            )
            c.commit()

    def add_watch(self, chat_id: str, url: str, target_price: Optional[float]) -> Tuple[bool, str]:
        now = datetime.now().isoformat()
        try:
            with self._conn() as c:
                cur = c.cursor()
                cur.execute(
                    'INSERT INTO rz_watches(chat_id,url,target_price,created_at,updated_at) VALUES(?,?,?,?,?)',
                    (chat_id, url, target_price, now, now)
                )
                c.commit()
            return True, 'Добавлено'
        except sqlite3.IntegrityError:
            return False, 'Уже есть в списке'
        except Exception as e:
            return False, f'Ошибка: {e}'

    def remove_watch(self, chat_id: str, key: str) -> int:
        with self._conn() as c:
            cur = c.cursor()
            if key.isdigit():
                cur.execute('DELETE FROM rz_watches WHERE chat_id=? AND id=?', (chat_id, int(key)))
            else:
                cur.execute('DELETE FROM rz_watches WHERE chat_id=? AND url=?', (chat_id, key))
            c.commit()
            return cur.rowcount

    def list_watches(self, chat_id: str) -> List[Dict[str, Any]]:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute('SELECT id,url,title,target_price,last_price,last_stock FROM rz_watches WHERE chat_id=? ORDER BY id DESC', (chat_id,))
            rows = cur.fetchall()
            out = []
            for r in rows:
                out.append({
                    'id': r[0], 'url': r[1], 'title': r[2] or '', 'target_price': r[3], 'last_price': r[4], 'last_stock': r[5]
                })
            return out

    def update_snapshot(self, chat_id: str, url: str, title: str, price: Optional[float], in_stock: Optional[bool]) -> None:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(
                'UPDATE rz_watches SET title=?, last_price=?, last_stock=?, updated_at=? WHERE chat_id=? AND url=?',
                (title, price, (1 if in_stock else 0) if in_stock is not None else None, datetime.now().isoformat(), chat_id, url)
            )
            c.commit()

    def all_watches(self) -> List[Tuple[str, str]]:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute('SELECT DISTINCT chat_id FROM rz_watches')
            chats = [r[0] for r in cur.fetchall()]
            out = []
            for cid in chats:
                cur.execute('SELECT url FROM rz_watches WHERE chat_id=?', (cid,))
                for (url,) in cur.fetchall():
                    out.append((cid, url))
            return out

    def add_query(self, chat_id: str, provider: str, query: str, max_price: Optional[float], min_rating: Optional[float]) -> Tuple[bool, str]:
        now = datetime.now().isoformat()
        with self._conn() as c:
            cur = c.cursor()
            try:
                cur.execute(
                    'INSERT INTO ts_query_watches(chat_id,provider,query,max_price,min_rating,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',
                    (chat_id, provider, query, max_price, min_rating, now, now)
                )
                c.commit()
                return True, 'Добавлено'
            except sqlite3.IntegrityError:
                return False, 'Уже есть'
            except Exception as e:
                return False, f'Ошибка: {e}'

    def list_queries(self, chat_id: str) -> List[Dict[str, Any]]:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute('SELECT id,provider,query,max_price,min_rating FROM ts_query_watches WHERE chat_id=? ORDER BY id DESC', (chat_id,))
            rows = cur.fetchall()
            return [
                {'id': r[0], 'provider': r[1], 'query': r[2], 'max_price': r[3], 'min_rating': r[4]}
                for r in rows
            ]

    def remove_query(self, chat_id: str, key: str) -> int:
        with self._conn() as c:
            cur = c.cursor()
            if key.isdigit():
                cur.execute('DELETE FROM ts_query_watches WHERE chat_id=? AND id=?', (chat_id, int(key)))
            else:
                cur.execute('DELETE FROM ts_query_watches WHERE chat_id=? AND query=?', (chat_id, key))
            c.commit()
            return cur.rowcount

    def all_queries(self) -> List[Tuple[str, str, str, Optional[float], Optional[float]]]:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute('SELECT chat_id,provider,query,max_price,min_rating FROM ts_query_watches')
            return [(r[0], r[1], r[2], r[3], r[4]) for r in cur.fetchall()]


class Notifier:
    def __init__(self, token: Optional[str], chat_id: Optional[str]):
        self.token = token
        self.chat_id = chat_id
        self._last_send: float = 0.0
        self.min_interval: float = float(os.getenv('TG_MIN_INTERVAL_MS') or 250) / 1000.0

    def _throttle(self) -> None:
        if self.min_interval <= 0:
            return
        now = time.time()
        dt = now - self._last_send
        if dt < self.min_interval:
            time.sleep(self.min_interval - dt)
        self._last_send = time.time()

    def send_chat_action(self, action: str = 'typing', chat_id: Optional[str] = None) -> bool:
        if not self.token:
            return False
        target = chat_id or self.chat_id
        if not target:
            return False
        url = f"https://api.telegram.org/bot{self.token}/sendChatAction"
        payload = {"chat_id": target, "action": action}
        data = urllib.parse.urlencode(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.getcode() < 300
        except Exception:
            return False

    def send(self, text: str, chat_id: Optional[str] = None, reply_markup: Optional[Dict[str, Any]] = None) -> bool:
        if not self.token:
            return False
        target = chat_id or self.chat_id
        if not target:
            return False
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload: Dict[str, Any] = {"chat_id": target, "text": text}
        if reply_markup is not None:
            payload["reply_markup"] = json.dumps(reply_markup)
        data = urllib.parse.urlencode(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        try:
            self._throttle()
            with urllib.request.urlopen(req, timeout=20) as resp:
                ok = 200 <= resp.getcode() < 300
                logger.debug('TG send to %s: %s (len=%d)', str(target), 'OK' if ok else f'HTTP {resp.getcode()}', len(text or ''))
                return ok
        except Exception:
            logger.exception('TG send failed to %s', str(target))
            return False

    def send_photo(self, photo_url: str, caption: str, chat_id: Optional[str] = None) -> bool:
        if not self.token:
            return False
        target = chat_id or self.chat_id
        if not target:
            return False
        url = f"https://api.telegram.org/bot{self.token}/sendPhoto"
        payload = {"chat_id": target, "photo": photo_url, "caption": caption[:1024]}
        data = urllib.parse.urlencode(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        try:
            self.send_chat_action('upload_photo', chat_id=target)
            self._throttle()
            with urllib.request.urlopen(req, timeout=20) as resp:
                return 200 <= resp.getcode() < 300
        except Exception:
            logger.exception('TG sendPhoto failed to %s', str(target))
            return False

    def send_media_group(self, items: List[Tuple[str, str]], chat_id: Optional[str] = None) -> bool:
        if not self.token or not items:
            return False
        target = chat_id or self.chat_id
        if not target:
            return False
        url = f"https://api.telegram.org/bot{self.token}/sendMediaGroup"
        media = []
        for i, (photo, cap) in enumerate(items[:10]):
            media.append({
                "type": "photo",
                "media": photo,
                "caption": cap[:1024] if i == 0 else cap[:1024]
            })
        payload = {"chat_id": target, "media": json.dumps(media)}
        data = urllib.parse.urlencode(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                return 200 <= resp.getcode() < 300
        except Exception:
            logger.exception('TG sendMediaGroup failed to %s', str(target))
            return False


def tg_get_updates(token: str, offset: int, timeout: int = 0) -> Tuple[int, List[Dict[str, Any]]]:
    base = f"https://api.telegram.org/bot{token}/getUpdates?timeout={timeout}&offset={offset}"
    try:
        with urllib.request.urlopen(base, timeout=timeout + 10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
    except Exception:
        logger.warning('TG getUpdates failed (timeout=%s)', timeout)
        return offset, []
    if not data.get('ok'):
        logger.warning('TG getUpdates returned not ok')
        return offset, []
    updates = data.get('result', [])
    if updates:
        offset = updates[-1]['update_id'] + 1
    if updates:
        logger.debug('TG updates: %d new', len(updates))
    return offset, updates


def parse_args(text: str) -> Tuple[str, List[str]]:
    t = (text or '').strip()
    if not t.startswith('/'):
        return '', []
    parts = t.split(maxsplit=1)
    cmd = parts[0].lower()
    rest = parts[1] if len(parts) > 1 else ''
    args = [a.strip() for a in rest.split()] if rest else []
    return cmd, args


def _main_keyboard() -> Dict[str, Any]:
    return {"keyboard": [
        [{"text": "/find"},{"text": "/watch"}],
        [{"text": "/my"},{"text": "/list"}],
        [{"text": "/check"},{"text": "/filters"}],
        [{"text": "/help"},{"text": "/menu"}]
    ], "resize_keyboard": True}

def handle_command(cmd: str, args: List[str], chat_id: str, storage: RZStorage, notifier: Notifier) -> None:
    logger.info('CMD %s args=%s from chat=%s', cmd, ' '.join(args), chat_id)
    allow_env = os.getenv('ALLOWED_CHAT_IDS')
    allowed: Optional[Set[str]] = None
    if allow_env:
        allowed = set(a.strip() for a in allow_env.split(',') if a.strip())
    if allowed is not None and allowed and chat_id not in allowed:
        logger.warning('Blocked command from unauthorized chat_id=%s', chat_id)
        return
    if cmd in ('/start','/menu'):
        notifier.send(
            "Команды:\n"
            " /find <запрос> [pages]\n"
            " /watch <запрос> [max_price] [min_rating]\n"
            " /my — подписки /stop <id|query> — удалить\n"
            " /list — URL трекинг /untrack <id|url>\n"
            " /track_url <url> [price]\n"
            " /filters show|set|reset\n"
            " /check — проверка сейчас\n"
            " /help — кратко /help full — подробно"
            , chat_id=chat_id, reply_markup=_main_keyboard()
        )
    elif cmd == '/help':
        if args and args[0].lower() in ('full','all','подробно'):
            notifier.send(
                "Подробно:\n"
                " /find <запрос> [pages] — поиск (магазины: comfy|prom|allo|foxtrot|eldorado|web|all: префикс перед запросом).\n"
                " /watch <запрос> [max_price] [min_rating] — слежение за запросом.\n"
                " /track_url <url> [price] — слежение за конкретной страницей.\n"
                " /my — запросы /stop <id|query> — удалить запрос.\n"
                " /list — URL слежение /untrack <id|url>.\n"
                " /filters show|set csv|reset — фильтр аксессуаров.\n"
                " /check — вручную проверить все слежения.\n"
                " /only <магазин> — показать сохранённые результаты по магазину.\n"
                " /more — ещё результаты последнего /find. /acc — аксессуары."
                , chat_id=chat_id, reply_markup=_main_keyboard()
            )
        else:
            notifier.send(
                "Кратко: /find /watch /my /list /track_url /filters /check /more /acc /only /stop /untrack. /help full — детали.",
                chat_id=chat_id, reply_markup=_main_keyboard()
            )
    elif cmd == '/loglevel':
        if not args:
            notifier.send('Использование: /loglevel <DEBUG|INFO|WARNING|ERROR>', chat_id=chat_id)
            return
        level = args[0].upper()
        lvl = getattr(logging, level, None)
        if not isinstance(lvl, int):
            notifier.send('Неверный уровень. Доступно: DEBUG, INFO, WARNING, ERROR', chat_id=chat_id)
            return
        logging.getLogger().setLevel(lvl)
        logger.setLevel(lvl)
        notifier.send(f'Уровень логов: {level}', chat_id=chat_id)
    elif cmd == '/filters':
        if not args or args[0].lower() == 'show':
            notifier.send(_filters_help(), chat_id=chat_id)
            return
        sub = args[0].lower()
        if sub == 'reset':
            try:
                os.environ.pop('ACCESSORY_BLOCKLIST', None)
            except Exception:
                pass
            notifier.send('ACCESSORY_BLOCKLIST сброшен к значению по умолчанию.', chat_id=chat_id)
            return
        if sub == 'set':
            csv = ' '.join(args[1:]).strip()
            os.environ['ACCESSORY_BLOCKLIST'] = csv
            notifier.send('ACCESSORY_BLOCKLIST обновлён.', chat_id=chat_id)
            return
        notifier.send('Использование: /filters show|set <csv>|reset', chat_id=chat_id)
    elif cmd == '/logfile':
            try:
                path = _LOG_FILE
            except Exception:
                path = '(нет файла лога)'
            notifier.send(f'Логи: {path}', chat_id=chat_id)
    elif cmd in ('/watch', '/track'):
        if not args:
            notifier.send('Использование: /watch <запрос> [max_price] [min_rating]\n(для URL: /track_url <url> [price])', chat_id=chat_id)
            return
        toks = list(args)
        def try_num(s: str):
            try:
                return float(s.replace(',', '.'))
            except Exception:
                return None
        provider: Optional[str] = None
        if toks:
            head = toks[0].lower()
            if head in ('comfy', 'prom', 'allo', 'foxtrot', 'eldorado', 'all'):
                provider = None if head == 'all' else head
                toks = toks[1:]
        if toks and ':' in toks[0]:
            prov, rest = toks[0].split(':', 1)
            if prov.lower() in ('comfy', 'prom', 'allo', 'foxtrot', 'eldorado', 'all'):
                provider = None if prov.lower() == 'all' else prov.lower()
                toks[0] = rest
        nums: List[float] = []
        while toks and len(nums) < 2:
            v = try_num(toks[-1])
            if v is None:
                break
            nums.append(v)  # last number first
            toks = toks[:-1]
        max_price: Optional[float] = None
        min_rating: Optional[float] = None
        if len(nums) == 1:
            max_price = nums[0]
        elif len(nums) >= 2:
            max_price = nums[1]
            min_rating = nums[0]
        query = ' '.join(toks).strip()
        if not query:
            notifier.send('Нужно указать текст запроса.', chat_id=chat_id)
            return
        items_all: List[Tuple[str, Product]] = []
        prov_map_all = _provider_map()
        base_order = ['comfy','allo','foxtrot','eldorado','prom']
        keys_ordered = [k for k in base_order if k in prov_map_all]
        to_add = [provider] if provider else keys_ordered
        for key in to_add:
            pr = prov_map_all.get(key)
            if not pr:
                continue
            try:
                max_pages = 1 if key == 'prom' else 1
                items = pr.search(query, max_pages=max_pages)
            except Exception:
                continue
            for p in items:
                items_all.append((key, p))
        if not items_all:
            notifier.send('Проверил сейчас: ничего не нашлось.', chat_id=chat_id)
            return
        def ok_by_threshold(p: Product) -> bool:
            if max_price is not None and (p.price is None or p.price > max_price):
                return False
            if min_rating is not None and p.rating is not None and p.rating < min_rating:
                return False
            return True
        wants_acc = _wants_accessory(query)
        filt = [(k, p) for (k, p) in items_all if (p.in_stock or p.price is not None) and ok_by_threshold(p) and (wants_acc or not _is_accessory(p.title))] or items_all[:6]
        seen: Set[str] = set()
        uniq: List[Tuple[str, Product]] = []
        for k, p in filt:
            key = _canonical_key(p)
            if key in seen:
                continue
            seen.add(key)
            uniq.append((k, p))
        if not uniq:
            notifier.send('Проверил сейчас: подходящих предложений не нашлось (по текущим порогам).', chat_id=chat_id)
            return
        priced = [p for _, p in uniq if p.price]
        best_price = min([p.price for p in priced], default=None)
        median_price = (statistics.median([p.price for p in priced]) if priced else None)
        scores: Dict[int, float] = {}
        for _, p in uniq:
            base = _score_product(p)
            wil = _wilson_lower_bound(p.rating, p.reviews)
            rel = _relevance_score(query, p.title)
            scores[id(p)] = 0.5*base + 0.3*wil + 0.2*rel
        sorted_items = sorted(uniq, key=lambda t: (t[1].price or 1e12))
        topK = set([id(p) for _, p in sorted(sorted_items, key=lambda t: scores.get(id(t[1]), 0), reverse=True)[:5]])
        main_items = [(k, p) for (k, p) in sorted_items if not _is_accessory(p.title)]
        acc_items = [(k, p) for (k, p) in sorted_items if _is_accessory(p.title)]
        LAST_RESULTS[chat_id] = {
            'query': query,
            'items': [(k, p.url, p.image, p.title, p.price, p.currency, p.rating, p.reviews, p.in_stock) for k, p in main_items],
            'acc': [(k, p.url, p.image, p.title, p.price, p.currency, p.rating, p.reviews, p.in_stock) for k, p in acc_items]
        }
        notifier.send_chat_action('typing', chat_id=chat_id)
        first_page = main_items[:10]
        sent = 0
        for k, p in first_page:
            caption = f"[{k}] {p.title[:80]}\n{p.url}\nЦена: {p.price or '—'} {p.currency or ''} | Рейтинг: {p.rating or '—'} ({p.reviews or 0}) | {'в наличии' if p.in_stock else '—'}"
            if p.image:
                notifier.send_photo(p.image, caption[:1024], chat_id=chat_id)
            else:
                notifier.send(caption[:3800], chat_id=chat_id)
            sent += 1
        if sent > 0:
            LAST_RESULTS[chat_id]['items'] = LAST_RESULTS[chat_id]['items'][sent:]
        if LAST_RESULTS[chat_id]['items'] or LAST_RESULTS[chat_id].get('acc'):
            kb = {"keyboard": [[{"text": "/more"}], [{"text": "/acc"}], [{"text": "/only comfy"},{"text": "/only allo"}], [{"text": "/only foxtrot"},{"text": "/only eldorado"}]], "one_time_keyboard": True, "resize_keyboard": True}
            notifier.send('Показать ещё / показать аксессуары / показать по магазину?', chat_id=chat_id, reply_markup=kb)
    elif cmd == '/track_url':
        if not args:
            notifier.send('Использование: /track_url <url> [price]', chat_id=chat_id)
            return
        url = args[0]
        tgt = None
        if len(args) > 1:
            try:
                tgt = float(args[1])
            except Exception:
                tgt = None
        ok, msg = storage.add_watch(chat_id, url, tgt)
        notifier.send(f"{msg}: {url}", chat_id=chat_id)
    elif cmd == '/list':
        items = storage.list_watches(chat_id)
        if not items:
            notifier.send('Список пуст.', chat_id=chat_id)
            return
        lines = []
        for it in items:
            status = '✅' if it.get('last_stock') else '—'
            price = it.get('last_price') if it.get('last_price') is not None else '—'
            lines.append(f"#{it['id']} {status} {price} | {it['url']}")
        notifier.send('\n'.join(lines[:50]), chat_id=chat_id)
    elif cmd in ('/my', '/listq'):
        items = storage.list_queries(chat_id)
        if not items:
            notifier.send('Список запросов пуст.', chat_id=chat_id)
            return
        lines = [f"#{it['id']} [{it['provider']}] {it['query']} | max_price={it['max_price'] or '—'} min_rating={it['min_rating'] or '—'}" for it in items]
        notifier.send('\n'.join(lines[:50]), chat_id=chat_id)
    elif cmd == '/untrack':
        if not args:
            notifier.send('Использование: /untrack <id|url>', chat_id=chat_id)
            return
        removed = storage.remove_watch(chat_id, args[0])
        notifier.send(f"Удалено: {removed}", chat_id=chat_id)
    elif cmd in ('/stop', '/unwatchq'):
        if not args:
            notifier.send('Использование: /stop <id|query>', chat_id=chat_id)
            return
        removed = storage.remove_query(chat_id, args[0])
        notifier.send(f"Удалено: {removed}", chat_id=chat_id)
    elif cmd == '/check':
        run_checks(storage, notifier, chat_id_only=chat_id)
    elif cmd == '/acc':
        rec = LAST_RESULTS.get(chat_id)
        if not rec:
            notifier.send('Сначала выполните /find.', chat_id=chat_id)
            return
        acc = rec.get('acc') or []
        if not acc:
            notifier.send('Аксессуаров не найдено.', chat_id=chat_id)
            return
        page = acc[:10]
        LAST_RESULTS[chat_id]['acc'] = acc[10:]
        notifier.send_chat_action('typing', chat_id=chat_id)
        for k, url, img, title, price, currency, rating, reviews, instock in page:
            caption = f"[{k}] {title[:80]}\n{url}\nЦена: {price or '—'} {currency or ''} | Рейтинг: {rating or '—'} ({reviews or 0}) | {'в наличии' if instock else '—'}"
            if img:
                notifier.send_photo(img, caption[:1024], chat_id=chat_id)
            else:
                notifier.send(caption[:3800], chat_id=chat_id)
        if LAST_RESULTS[chat_id].get('acc'):
            kb = {"keyboard": [[{"text": "/acc"}]], "one_time_keyboard": True, "resize_keyboard": True}
            notifier.send('Ещё аксессуары?', chat_id=chat_id, reply_markup=kb)
    elif cmd == '/only':
        if not args:
            notifier.send('Использование: /only <comfy|allo|foxtrot|eldorado|prom>', chat_id=chat_id)
            return
        prov = args[0].lower()
        rec = LAST_RESULTS.get(chat_id)
        if not rec:
            notifier.send('Сначала выполните /find.', chat_id=chat_id)
            return
        all_items = rec.get('items') or []
        if not all_items:
            notifier.send('Нет сохранённых результатов.', chat_id=chat_id)
            return
        subset = [it for it in all_items if it and it[0].lower() == prov]
        if not subset:
            notifier.send('Нет результатов для выбранного магазина.', chat_id=chat_id)
            return
        page = subset[:10]
        notifier.send_chat_action('typing', chat_id=chat_id)
        for k, url, img, title, price, currency, rating, reviews, instock in page:
            caption = f"[{k}] {title[:80]}\n{url}\nЦена: {price or '—'} {currency or ''} | Рейтинг: {rating or '—'} ({reviews or 0}) | {'в наличии' if instock else '—'}"
            if img:
                notifier.send_photo(img, caption[:1024], chat_id=chat_id)
            else:
                notifier.send(caption[:3800], chat_id=chat_id)
    elif cmd == '/more':
        rec = LAST_RESULTS.get(chat_id)
        if not rec:
            notifier.send('Нет сохранённых результатов. Сначала сделайте /find.', chat_id=chat_id)
            return
        items = rec.get('items') or []
        if not items:
            notifier.send('Больше результатов нет.', chat_id=chat_id)
            return
        page = items[:10]
        LAST_RESULTS[chat_id]['items'] = items[10:]
        notifier.send_chat_action('typing', chat_id=chat_id)
        for k, url, img, title, price, currency, rating, reviews, instock in page:
            caption = f"[{k}] {title[:80]}\n{url}\nЦена: {price or '—'} {currency or ''} | Рейтинг: {rating or '—'} ({reviews or 0}) | {'в наличии' if instock else '—'}"
            if img:
                notifier.send_photo(img, caption[:1024], chat_id=chat_id)
            else:
                notifier.send(caption[:3800], chat_id=chat_id)
    elif cmd in ('/best', '/find'):
        if not args:
            notifier.send('Использование: /find <запрос> [pages]\n(без префикса — все магазины; можно: comfy|prom|allo|foxtrot|eldorado|all)', chat_id=chat_id)
            return
        notifier.send_chat_action('typing', chat_id=chat_id)
        notifier.send('Подождите минутку, собираю предложения и пришлю ссылки на товары…', chat_id=chat_id)
        query_raw = ' '.join(args[:-1]) if len(args) > 1 and args[-1].isdigit() else ' '.join(args)
        pages = int(args[-1]) if len(args) > 1 and args[-1].isdigit() else 1
        provider: Optional[str] = None
        q = query_raw.strip()
        if ':' in q.split()[0]:
            prov, rest = q.split(':', 1)
            if prov.lower() in ('comfy', 'prom', 'allo', 'foxtrot', 'eldorado', 'web', 'all'):
                provider = None if prov.lower() == 'all' else prov.lower()
                q = rest.strip()
        else:
            head = (q.split() or [''])[0].lower()
            if head in ('comfy', 'prom', 'allo', 'foxtrot', 'eldorado', 'web', 'all'):
                provider = None if head == 'all' else head
                q = ' '.join(q.split()[1:])
        prov_map = _provider_map()
        keys = [provider] if provider else list(prov_map.keys())
        items_all: List[Tuple[str, Product]] = []
        for k in keys:
            pr = prov_map.get(k)
            if not pr:
                continue
            items = pr.search(q, max_pages=max(1, min(2, pages)))
            for p in items:
                items_all.append((k, p))
        if not items_all:
            notifier.send('Ничего не нашлось.', chat_id=chat_id)
            return
        seen: Set[str] = set()
        agg: List[Tuple[str, Product]] = []
        for k, p in items_all:
            key = _canonical_key(p)
            if key in seen:
                continue
            seen.add(key)
            agg.append((k, p))
        wants_acc = _wants_accessory(q)
        filtered = [(k, p) for (k, p) in agg if wants_acc or not _is_accessory(p.title)] or agg
        priced = [p for _, p in filtered if p.price]
        best_price = min([p.price for p in priced], default=None)
        median_price = (statistics.median([p.price for p in priced]) if priced else None)
        scored = []
        for kp in filtered:
            _, p = kp
            base = _score_product(p)
            wil = _wilson_lower_bound(p.rating, p.reviews)
            rel = _relevance_score(q, p.title)
            scored.append((0.5*base + 0.3*wil + 0.2*rel, kp))
        sorted_items = [kp for _, kp in sorted(scored, key=lambda t: t[0], reverse=True)]
        LAST_RESULTS[chat_id] = {
            'query': q,
            'items': [(k, p.url, p.image, p.title, p.price, p.currency, p.rating, p.reviews, p.in_stock) for (k, p) in sorted_items]
        }
        to_send = sorted_items[:10]
        notifier.send_chat_action('typing', chat_id=chat_id)
        sent = 0
        for k, p in to_send:
            marks = []
            if best_price is not None and p.price is not None and abs(p.price - best_price) < 1e-6:
                marks.append('💰')
            marks.append('🔥')
            if median_price is not None and p.price is not None and p.price < median_price*0.9:
                marks.append('📉')
            tag = ''.join(marks) + ' '
            caption = f"[{k}] {tag}{p.title[:80]}\n{p.url}\nЦена: {p.price or '—'} {p.currency or ''} | Рейтинг: {p.rating or '—'} ({p.reviews or 0}) | {'в наличии' if p.in_stock else '—'}"
            if p.image:
                notifier.send_photo(p.image, caption[:1024], chat_id=chat_id)
            else:
                notifier.send(caption[:3800], chat_id=chat_id)
            sent += 1
        if len(sorted_items) > sent:
            kb = {"keyboard": [[{"text": "/more"}]], "one_time_keyboard": True, "resize_keyboard": True}
            notifier.send('Показать ещё?', chat_id=chat_id, reply_markup=kb)
    else:
        notifier.send('Неизвестная команда. /help', chat_id=chat_id)


def run_checks(storage: RZStorage, notifier: Notifier, chat_id_only: Optional[str] = None) -> None:
    logger.info('run_checks start (chat_only=%s)', str(chat_id_only))
    if chat_id_only:
        pairs = []
        for it in storage.list_watches(chat_id_only):
            pairs.append((chat_id_only, it['url']))
    else:
        pairs = storage.all_watches()
    logger.debug('URL watches to check: %d', len(pairs))
    for chat_id, url in pairs:
        try:
            p = fetch_product(url)
        except Exception:
            logger.exception('URL check failed: %s', url)
            continue
        storage.update_snapshot(chat_id, url, p.title, p.price, p.in_stock)
        lines = []
        if p.in_stock:
            lines.append('✅ В наличии')
        else:
            lines.append('— Нет в наличии')
        if p.price is not None:
            lines.append(f"Цена: {p.price} {p.currency or ''}")
        title = p.title or 'Товар'
        msg = f"{title}\n{url}\n" + ' | '.join(lines)
        if p.in_stock or p.price is not None:
            sent = notifier.send(msg, chat_id=chat_id)
            logger.debug('Notify URL watch sent=%s for %s', str(sent), url)

    def ok_by_threshold(p: Product, max_price: Optional[float], min_rating: Optional[float]) -> bool:
        if max_price is not None and (p.price is None or p.price > max_price):
            return False
        if min_rating is not None and p.rating is not None and p.rating < min_rating:
            return False
        return True

    q_items = storage.list_queries(chat_id_only) if chat_id_only else None
    if chat_id_only and not q_items:
        pass
    providers: Dict[str, Provider] = _provider_map()
    if chat_id_only:
        tuples = [(chat_id_only, it['provider'], it['query'], it['max_price'], it['min_rating']) for it in (q_items or [])]
    else:
        tuples = []
        for cid, prov, query, mxp, minr in storage.all_queries():
            tuples.append((cid, prov, query, mxp, minr))
    budget_start = time.time()
    BUDGET_SEC = 20.0
    from collections import defaultdict
    grouped: Dict[Tuple[str, str], List[Tuple[str, Optional[float], Optional[float]]]] = defaultdict(list)
    for cid, prov, q, max_price, min_rating in tuples:
        grouped[(cid, q)].append((prov, max_price, min_rating))

    for (cid, q), prov_reqs in grouped.items():
        if time.time() - budget_start > BUDGET_SEC:
            logger.info('run_checks budget exceeded, stopping early')
            break
        items_all: List[Tuple[str, Product]] = []
        max_price = None
        min_rating = None
        for prov, mp, mr in prov_reqs:
            pr = providers.get(prov)
            if not pr:
                continue
            try:
                items = pr.search(q, max_pages=1)
            except Exception:
                logger.exception('Query search failed [%s]: %s', prov, q)
                continue
            for p in items:
                items_all.append((prov, p))
            if mp is not None:
                max_price = mp if (max_price is None or mp < max_price) else max_price
            if mr is not None:
                min_rating = mr if (min_rating is None or mr > min_rating) else min_rating
        if not items_all:
            continue
        wants_acc = _wants_accessory(q)
        filt = [(k, p) for (k, p) in items_all if (p.in_stock or p.price is not None) and ok_by_threshold(p, max_price, min_rating) and (wants_acc or not _is_accessory(p.title))] or items_all[:6]
        seen: Set[str] = set()
        uniq: List[Tuple[str, Product]] = []
        for k, p in filt:
            key = _canonical_key(p)
            if key in seen:
                continue
            seen.add(key)
            uniq.append((k, p))
        if not uniq:
            continue
        priced = [p for _, p in uniq if p.price]
        best_price = min([p.price for p in priced], default=None)
        median_price = (statistics.median([p.price for p in priced]) if priced else None)
        scored = []
        for kp in uniq:
            _, p = kp
            base = _score_product(p)
            wil = _wilson_lower_bound(p.rating, p.reviews)
            rel = _relevance_score(q, p.title)
            scored.append((0.5*base + 0.3*wil + 0.2*rel, kp))
        scored = [kp for _, kp in sorted(scored, key=lambda t: t[0], reverse=True)[:10]]
        lines = [f"{q}"]
        for k, p in scored:
            marks = []
            if best_price is not None and p.price is not None and abs(p.price - best_price) < 1e-6:
                marks.append('💰')
            marks.append('🔥')
            if median_price is not None and p.price is not None and p.price < median_price*0.9:
                marks.append('📉')
            tag = ''.join(marks) + ' '
            caption = f"[{k}] {tag}{p.title[:80]}\n{p.url}\nЦена: {p.price or '—'} {p.currency or ''} | Рейтинг: {p.rating or '—'} ({p.reviews or 0}) | {'в наличии' if p.in_stock else '—'}"
            lines.append(caption)
        for line in lines[1:11]:
            try:
                url = line.split('\n', 2)[1]
            except Exception:
                url = ''
            img = None
            for k, p in scored:
                if p.url == url and p.image:
                    img = p.image
                    break
            if img:
                notifier.send_photo(img, line[:1024], chat_id=cid)
            else:
                notifier.send(line[:3800], chat_id=cid)
    logger.debug('Notify query sent items for "%s" (providers=%d)', q, len(prov_reqs))


def _setup_shutdown_handlers(notifier: Notifier, chat_id_default: Optional[str]) -> None:
    try:
        import signal
    except Exception:
        return
    def _handler(signum, frame):
        try:
            if notifier and notifier.token and chat_id_default:
                notifier.send('TovarScout остановлен ⛔', chat_id=chat_id_default)
        finally:
            os._exit(0)
    for name in ('SIGINT', 'SIGTERM', 'SIGBREAK'):
        s = getattr(signal, name, None)
        if s is not None:
            try:
                signal.signal(s, _handler)
            except Exception:
                pass
            
def main() -> None:
    secrets = _load_secrets()
    # Token priority: TELEGRAM_BOT_TOKEN > TELEGRAM_TOKEN > env vars
    token = (
        secrets.get('TELEGRAM_BOT_TOKEN') or
        secrets.get('TELEGRAM_TOKEN') or
        os.getenv('TELEGRAM_BOT_TOKEN') or
        os.getenv('TELEGRAM_TOKEN')
    )
    if not token:
        logger.error('Не найден TELEGRAM_BOT_TOKEN/TELEGRAM_TOKEN в secrets.json или переменных окружения')
        return
    chat_default = (
        secrets.get('TELEGRAM_CHAT_ID') or
        os.getenv('TELEGRAM_CHAT_ID')
    )
    # Log level
    lvl = (secrets.get('LOG_LEVEL') or os.getenv('LOG_LEVEL') or 'INFO').upper()
    if hasattr(logging, lvl):
        logging.getLogger().setLevel(getattr(logging, lvl))
        logger.setLevel(getattr(logging, lvl))
    # DB path optional
    db_path = secrets.get('DB_PATH') or os.getenv('DB_PATH')
    storage = RZStorage(db_path=db_path)
    notifier = Notifier(token, chat_default)
    if chat_default:
        try:
            notifier.send('TovarScout запущен ✅', chat_id=chat_default)
        except Exception:
            pass
    _setup_shutdown_handlers(notifier, chat_default)
    offset = 0
    # Flush backlog updates so bot doesn't react to old messages (e.g. "телевизор").
    try:
        for _ in range(10):  # safety loop
            new_offset, updates = tg_get_updates(token, offset, timeout=0)
            if not updates:
                offset = new_offset
                break
            offset = new_offset
        logger.info('Flushed old updates, start offset=%s', offset)
    except Exception:
        logger.exception('Failed to flush old updates; continuing')
    # Prevent immediate auto run: start counting from now.
    last_check = time.time()
    check_interval = float(secrets.get('CHECK_INTERVAL_SEC') or os.getenv('CHECK_INTERVAL_SEC') or 600)
    disable_auto = (os.getenv('DISABLE_AUTO_CHECKS') == '1')
    while True:
        try:
            # Long polling
            offset, updates = tg_get_updates(token, offset, timeout=25)
            for upd in updates:
                msg = upd.get('message') or upd.get('edited_message') or {}
                text = msg.get('text') or ''
                chat = msg.get('chat') or {}
                chat_id = str(chat.get('id')) if chat.get('id') is not None else None
                if not chat_id or not text:
                    continue
                if text.startswith('/'):
                    cmd, args = parse_args(text)
                    if cmd:
                        handle_command(cmd, args, chat_id, storage, notifier)
                # Plain text now ignored unless you explicitly use commands.
            # Periodic checks
            now = time.time()
            if (not disable_auto) and (now - last_check >= check_interval):
                try:
                    run_checks(storage, notifier)
                except Exception:
                    logger.exception('run_checks failed')
                last_check = now
        except KeyboardInterrupt:
            break
        except Exception:
            logger.exception('Main loop error, спим 5с')
            time.sleep(5)
    if chat_default:
        try:
            notifier.send('TovarScout остановлен ⛔', chat_id=chat_default)
        except Exception:
            pass
            
if __name__ == '__main__':
    main()
