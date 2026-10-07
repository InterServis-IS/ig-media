#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Серверный публикатор Reels для Instagram.

Зачем. Программа «Диалог Деск» публикует по расписанию, пока включён компьютер и
есть интернет. Здесь то же расписание работает на сервере, который не
выключается: ролики лежат на сервере, в нужный час сервер сам кладёт ролик на
GitHub (быстрым серверным каналом), просит Instagram забрать его оттуда,
дожидается обработки и публикует. Интернет вашего компьютера в этой цепочке не
участвует.

⚠️ Почему ролик идёт через GitHub, а не лежит на самом сервере. Серверы Meta не
доходят до серверов в России (в журналах IIS от них не было ни одного запроса),
поэтому Instagram должен забирать файл с хостинга, до которого он дотягивается.
То же самое делает и приложение на компьютере.

Запуск: раз в минуту из планировщика Windows (команда run). Одна минута = один
короткий заход: посмотреть расписание, при необходимости выложить следующий ролик.

Только стандартная библиотека Python 3.8+. Ничего ставить не нужно.

Команды:
  run                     один заход (для планировщика)
  status                  очередь, ближайшие выходы, последние попытки
  check                   проверить доступность Instagram и GitHub, токены, ролик — ничего не публикуя
  publish-now АККАУНТ --yes   выложить следующий ролик сейчас (настоящая публикация)
  mark-published ИМЯ.mp4 [--account АККАУНТ]   считать ролик уже вышедшим
  forget ИМЯ.mp4 [--account АККАУНТ]           вернуть ролик в очередь
  fetch-inbox АККАУНТ [--from inbox]           скачать с GitHub (из папки inbox репозитория) ролики и подписи в папку аккаунта
"""
import argparse
import base64
import http.client
import json
import os
import random
import re
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

API_HOST_DEFAULT = 'https://graph.instagram.com'
API_VERSION = 'v25.0'
GITHUB_API_DEFAULT = 'https://api.github.com'
GITHUB_RAW_DEFAULT = 'https://raw.githubusercontent.com'
VIDEO_EXT = ('.mp4', '.mov')
MAX_BYTES = 300 * 1024 * 1024
MAX_CAPTION = 2200
MAX_HISTORY = 200
REPEAT_AFTER_MIN = 25      # через сколько пробуем слот заново после неудачи
ATTEMPTS_PER_DAY = 3       # сколько попыток на слот в сутки
LOCK_STALE_SEC = 30 * 60
REEL_WAIT_SEC = 12 * 60    # сколько ждём, пока Instagram обработает ролик
POLL_SEC = 10
TOKEN_REFRESH_DAYS = 30
HOLD_AFTER_UNCERTAIN_MIN = 30
UPLOAD_ATTEMPTS = 3
FILE_NAME = re.compile(r'^ig-([0-9a-z]{5,12})-[0-9a-z]{2,12}(?:-\d{1,3})?\.(?:jpg|jpeg|png|mp4|mov)$')

HERE = os.path.dirname(os.path.abspath(__file__))


# ─── мелочи ─────────────────────────────────────────────────────────────

def read_text(path):
    """Текст файла: UTF-8 (с BOM или без), а если это «старый» Блокнот с кодировкой Windows-1251 — и она."""
    with open(path, 'rb') as fh:
        raw = fh.read()
    try:
        return raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        return raw.decode('cp1251', 'replace')


def load_json(path, default):
    try:
        return json.loads(read_text(path))
    except FileNotFoundError:
        return default


def save_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def to_base36(number):
    digits = '0123456789abcdefghijklmnopqrstuvwxyz'
    out = ''
    while number:
        number, rest = divmod(number, 36)
        out = digits[rest] + out
    return out or '0'


# ─── SOCKS5 без сторонних библиотек (если у прокси именно такой адрес: socks5://...) ─────

def socks5_connect(proxy_url, host, port, timeout):
    """Соединение с host:port через SOCKS5-прокси. Имя сайта отдаём прокси целиком: DNS решает он, а не сервер."""
    u = urllib.parse.urlparse(proxy_url)
    sock = socket.create_connection((u.hostname, u.port or 1080), timeout=timeout)
    try:
        user, pwd = urllib.parse.unquote(u.username or ''), urllib.parse.unquote(u.password or '')
        sock.sendall(b'\x05\x02\x00\x02' if user else b'\x05\x01\x00')
        ver, method = sock.recv(2)
        if ver != 5 or method == 0xFF:
            raise OSError('SOCKS5-прокси не принял способ входа')
        if method == 2:
            sock.sendall(b'\x01' + bytes([len(user.encode())]) + user.encode() + bytes([len(pwd.encode())]) + pwd.encode())
            if sock.recv(2)[1] != 0:
                raise OSError('SOCKS5-прокси не принял логин/пароль')
        name = host.encode('idna')
        sock.sendall(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + struct.pack('>H', port))
        head = _read_exact(sock, 4)
        if head[1] != 0:
            raise OSError('SOCKS5-прокси не смог соединиться с %s:%s (код %d)' % (host, port, head[1]))
        _read_exact(sock, {1: 4, 4: 16}.get(head[3], 0) if head[3] != 3 else _read_exact(sock, 1)[0])
        _read_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def _read_exact(sock, n):
    out = b''
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise OSError('SOCKS5-прокси оборвал соединение')
        out += chunk
    return out


class _SocksHTTPConnection(http.client.HTTPConnection):
    proxy_url = ''

    def connect(self):
        self.sock = socks5_connect(self.proxy_url, self.host, self.port, self.timeout)


class _SocksHTTPSConnection(http.client.HTTPSConnection):
    proxy_url = ''

    def connect(self):
        raw = socks5_connect(self.proxy_url, self.host, self.port, self.timeout)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)


class _SocksHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, proxy_url):
        urllib.request.HTTPHandler.__init__(self)
        self.cls = type('C', (_SocksHTTPConnection,), {'proxy_url': proxy_url})

    def http_open(self, req):
        return self.do_open(self.cls, req)


class _SocksHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, proxy_url):
        urllib.request.HTTPSHandler.__init__(self)
        self.cls = type('C', (_SocksHTTPSConnection,), {'proxy_url': proxy_url})

    def https_open(self, req):
        return self.do_open(self.cls, req)


class Ctx(object):
    """Всё, что нужно заходу: настройки, состояние, часы и журнал."""

    def __init__(self, base_dir, now=None):
        self.dir = base_dir
        self.cfg = load_json(os.path.join(base_dir, 'config.json'), None)
        if self.cfg is None:
            raise SystemExit('Нет файла config.json рядом с ig_publisher.py (образец: config.example.json).')
        self.state_path = os.path.join(base_dir, 'state.json')
        self.state = load_json(self.state_path, {})
        self.log_path = os.path.join(base_dir, 'publisher.log')
        self.tz = timezone(timedelta(hours=float(self.cfg.get('utc_offset_hours', 3))))
        self._now = now
        self.api_host = str(self.cfg.get('api_host') or API_HOST_DEFAULT).rstrip('/')
        self.github_api = str(self.cfg.get('github_api_host') or GITHUB_API_DEFAULT).rstrip('/')
        self.github_raw = str(self.cfg.get('github_raw_host') or GITHUB_RAW_DEFAULT).rstrip('/')
        self.sleep = time.sleep
        self._openers = {}

    def now(self):
        return self._now() if self._now else datetime.now(self.tz)

    def save(self):
        save_json(self.state_path, self.state)

    def installed_at(self):
        """Момент первого захода. Слоты, которые наступили раньше, не догоняем: иначе установка
        в середине дня выложила бы ролик сразу, а приложение на компьютере могло уже сделать то же."""
        raw = parse_iso(self.state.get('installed_at'))
        if raw is None:
            raw = self.now()
            self.state['installed_at'] = raw.isoformat()
            self.save()
        return raw

    def acc_state(self, name):
        st = self.state.setdefault('accounts', {}).setdefault(name, {})
        st.setdefault('history', [])
        st.setdefault('published', {})
        st.setdefault('pending_delete', [])
        return st

    def log(self, text):
        line = '%s  %s' % (self.now().strftime('%Y-%m-%d %H:%M:%S'), text)
        try:
            if os.path.exists(self.log_path) and os.path.getsize(self.log_path) > 2 * 1024 * 1024:
                os.replace(self.log_path, self.log_path + '.old')
            with open(self.log_path, 'a', encoding='utf-8') as fh:
                fh.write(line + '\n')
        except OSError:
            pass
        print(line)

    def opener(self, kind):
        """kind: 'instagram' | 'github' | 'plain'. Прокси (если задан) нужен не всем адресам."""
        if kind not in self._openers:
            proxy = str(self.cfg.get('proxy') or '').strip()
            use = proxy and kind in (self.cfg.get('proxy_for') or ['instagram'])
            if use and proxy.lower().startswith(('socks5://', 'socks5h://')):
                handlers = [urllib.request.ProxyHandler({}), _SocksHTTPHandler(proxy), _SocksHTTPSHandler(proxy)]
            elif use:
                handlers = [urllib.request.ProxyHandler({'http': proxy, 'https': proxy})]
            else:
                handlers = [urllib.request.ProxyHandler({})]
            self._openers[kind] = urllib.request.build_opener(*handlers)
        return self._openers[kind]

    def notify(self, text):
        """Сообщение владельцу в Telegram, если это настроено. Сбой уведомления публикацию не трогает."""
        tg = self.cfg.get('notify') or {}
        token, chat = str(tg.get('telegram_bot_token') or ''), str(tg.get('telegram_chat_id') or '')
        if not token or not chat:
            return
        try:
            data = urllib.parse.urlencode({'chat_id': chat, 'text': text[:3500]}).encode('utf-8')
            self.opener('plain').open('https://api.telegram.org/bot%s/sendMessage' % token, data=data, timeout=20).read()
        except Exception as error:  # noqa: BLE001
            self.log('Не удалось отправить уведомление в Telegram: %s' % str(error)[:120])


# ─── расписание: те же правила, что в приложении (lib/igschedule.js) ─────

def minutes_of(value):
    m = re.match(r'^(\d{1,2}):(\d{2})$', str(value or '').strip())
    if not m:
        return 600
    h, mi = int(m.group(1)), int(m.group(2))
    return h * 60 + mi if (0 <= h <= 23 and 0 <= mi <= 59) else 600


def weekday_of(dt):
    return dt.isoweekday()  # понедельник — 1, воскресенье — 7


def slot_time(slot, day):
    start = day.replace(hour=0, minute=0, second=0, microsecond=0)
    return start + timedelta(minutes=minutes_of(slot.get('time')))


def parse_iso(text):
    raw = str(text or '').strip()
    if raw.endswith('Z'):
        raw = raw[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def same_day(a, b, tz):
    return a.astimezone(tz).date() == b.astimezone(tz).date()


def slot_attempts(history, slot_id, now, tz):
    out = []
    for rec in history:
        at = parse_iso(rec.get('at'))
        if rec.get('slotId') == slot_id and at and same_day(at, now, tz):
            out.append((rec, at))
    return out


def done_today(history, slot_id, now, tz):
    attempts = slot_attempts(history, slot_id, now, tz)
    if not attempts:
        return False
    if any(rec.get('ok') or rec.get('uncertain') for rec, _ in attempts):
        return True
    if len(attempts) >= ATTEMPTS_PER_DAY:
        return True
    last = max(at for _, at in attempts)
    return (now - last) < timedelta(minutes=REPEAT_AFTER_MIN)


def clamp(value, low, high, fallback):
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError):
        return fallback
    return max(low, min(high, number))


def due_slot(acc, history, now, tz, not_before=None):
    """Что пора публиковать прямо сейчас: (слот или None, причина).
    not_before — слоты, чьё время наступило раньше установки сервера, не догоняем."""
    slots = [s for s in acc.get('slots', []) if s.get('enabled', True) and clamp(s.get('weekday'), 1, 7, 1) == weekday_of(now)]
    pairs = sorted(((s, slot_time(s, now)) for s in slots), key=lambda p: p[1])
    pairs = [p for p in pairs if p[1] <= now]
    if not pairs:
        return None, 'сегодня время ещё не подошло'
    waiting = [p for p in pairs if not done_today(history, p[0]['id'], now, tz)]
    if not waiting:
        return None, 'всё сегодняшнее уже вышло'
    if not_before is not None:
        waiting = [p for p in waiting if p[1] >= not_before]
        if not waiting:
            return None, 'слот наступил до установки сервера — не догоняю (чтобы не задвоить с приложением)'
    late = timedelta(minutes=clamp(acc.get('late_minutes', 180), 10, 12 * 60, 180))
    fresh = [p for p in waiting if now - p[1] <= late]
    if not fresh:
        return None, 'время слота прошло больше чем на срок опоздания'
    slot = fresh[0][0]
    ok_today = [r for r in history if r.get('ok') and parse_iso(r.get('at')) and same_day(parse_iso(r['at']), now, tz)]
    limit = clamp(acc.get('daily_limit', 3), 1, 10, 3)
    if len(ok_today) >= limit:
        return None, 'сегодня уже %d публикаций из %d' % (len(ok_today), limit)
    oks = [parse_iso(r['at']) for r in history if r.get('ok') and parse_iso(r.get('at'))]
    last_ok = max(oks) if oks else None
    gap_min = clamp(acc.get('min_gap_minutes', 90), 0, 24 * 60, 90)
    gap = timedelta(minutes=gap_min)
    if last_ok and now - last_ok < gap:
        left = int(-(-(gap - (now - last_ok)).total_seconds() // 60))
        return None, 'после прошлой публикации не прошло %d минут (ждать ещё %d)' % (gap_min, left)
    return slot, ''


def next_runs(acc, now, limit=5):
    out = []
    for shift in range(0, 8):
        day = now + timedelta(days=shift)
        for s in acc.get('slots', []):
            if s.get('enabled', True) and clamp(s.get('weekday'), 1, 7, 1) == weekday_of(day):
                at = slot_time(s, day)
                if at > now:
                    out.append((at, s))
    out.sort(key=lambda p: p[0])
    return out[:limit]


# ─── очередь роликов ─────────────────────────────────────────────────────

def natural_key(name):
    return [int(p) if p.isdigit() else p.lower() for p in re.split(r'(\d+)', name)]


def read_queue(acc, st):
    folder = acc.get('videos_dir', '')
    try:
        names = sorted([n for n in os.listdir(folder) if n.lower().endswith(VIDEO_EXT) and not n.startswith(('.', '~'))], key=natural_key)
    except OSError as error:
        return {'items': [], 'next': None, 'error': 'папка недоступна: %s' % str(error)[:120]}
    done = set(st['published'].keys()) | set(acc.get('already_published', []))
    items = []
    for n in names:
        path = os.path.join(folder, n)
        cap = os.path.join(folder, os.path.splitext(n)[0] + '.txt')
        items.append({'name': n, 'path': path, 'size': os.path.getsize(path), 'caption_path': cap,
                      'has_caption': os.path.exists(cap), 'published': n in done})
    nxt = next((i for i in items if not i['published']), None)
    return {'items': items, 'next': nxt, 'error': ''}


def read_caption(item):
    if not item or not item['has_caption']:
        return ''
    return read_text(item['caption_path']).replace('\r\n', '\n').strip()[:MAX_CAPTION]


def video_problem(item, caption):
    if not item:
        return 'в папке нет видео'
    if not item['size']:
        return 'файл «%s» пустой' % item['name']
    if item['size'] > MAX_BYTES:
        return 'файл «%s» больше 300 МБ — Instagram такой не примет' % item['name']
    if not caption:
        return 'у «%s» нет подписи: положите рядом файл %s с текстом поста' % (item['name'], os.path.splitext(item['name'])[0] + '.txt')
    return ''


# ─── сеть ───────────────────────────────────────────────────────────────

class ApiError(Exception):
    def __init__(self, message, code=0, status=0, definite=True, retry=False):
        Exception.__init__(self, message)
        self.code, self.status, self.definite, self.retry = code, status, definite, retry


def http(ctx, kind, method, url, headers=None, data=None, timeout=60):
    """Один запрос. Возвращает (статус, заголовки, тело-байты); сеть/таймаут → ApiError(definite=False)."""
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with ctx.opener(kind).open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()
    except Exception as error:  # noqa: BLE001  сеть, таймаут, DNS: исход неизвестен
        raise ApiError('нет связи (%s): %s' % (urllib.parse.urlparse(url).hostname, str(error)[:120]), definite=False, retry=True)


# ─── Instagram API ──────────────────────────────────────────────────────

def describe_api_error(err, status):
    code = int(err.get('code') or 0)
    text = str(err.get('message') or '')[:200]
    if code == 190 or status == 401:
        return 'Instagram не принял токен — он истёк или отозван: выпустите новый и вставьте в config.json (%s)' % text
    if code in (4, 17, 32):
        return 'Instagram просит подождать (лимит запросов): %s' % text
    if code in (9007, 2207027):
        return 'Instagram ещё не закончил обработку ролика: %s' % text
    return 'Instagram ответил ошибкой %s: %s' % (code or status, text)


def api(ctx, method, path, token, params=None, timeout=60):
    params = dict(params or {})
    params['access_token'] = token
    if path.startswith('refresh_access_token'):
        url = '%s/%s' % (ctx.api_host, path)
    else:
        url = '%s/%s/%s' % (ctx.api_host, API_VERSION, path)
    data = None
    if method == 'GET':
        url += '?' + urllib.parse.urlencode(params)
    else:
        data = urllib.parse.urlencode(params).encode('utf-8')
    status, _, raw = http(ctx, 'instagram', method, url, data=data, timeout=timeout)
    try:
        obj = json.loads(raw.decode('utf-8', 'replace'))
    except ValueError:
        obj = {}
    if status >= 400 or obj.get('error'):
        err = obj.get('error') or {'message': 'HTTP %s' % status}
        # 5xx — исход тоже неизвестен: пост мог выйти.
        raise ApiError(describe_api_error(err, status), code=int(err.get('code') or 0), status=status, definite=status < 500)
    return obj


def ensure_token(ctx, acc, st):
    """Токен из config.json; после продления живёт в state.json. Продлеваем раз в 30 дней."""
    seed = str(acc.get('token') or '').strip()
    if not seed or seed.startswith('ВСТАВЬТЕ'):
        raise ApiError('в config.json не вставлен токен Instagram аккаунта «%s»' % acc['name'])
    if st.get('seed') != seed:                      # токен в config поменяли — он главнее
        st.update({'seed': seed, 'token': seed, 'refreshed_at': ctx.now().isoformat()})
        ctx.save()
    token = st['token']
    last = parse_iso(st.get('refreshed_at')) or ctx.now()
    age = ctx.now() - last
    if age >= timedelta(days=TOKEN_REFRESH_DAYS):
        try:
            res = api(ctx, 'GET', 'refresh_access_token', token, {'grant_type': 'ig_refresh_token'})
            if res.get('access_token'):
                st['token'], st['refreshed_at'] = res['access_token'], ctx.now().isoformat()
                ctx.save()
                token = st['token']
                ctx.log('[%s] токен Instagram продлён ещё на 60 дней' % acc['name'])
        except ApiError as error:
            ctx.log('[%s] не удалось продлить токен: %s' % (acc['name'], error))
            if age >= timedelta(days=50):
                ctx.notify('⚠️ Instagram «%s»: токен скоро истечёт, продление не удалось: %s' % (acc['name'], error))
    return token


def already_posted(ctx, token, caption):
    """Страховка от дубля: если такой же текст уже в ленте (например, выложило приложение на ПК), второй раз не публикуем."""
    try:
        res = api(ctx, 'GET', 'me/media', token, {'fields': 'id,caption,timestamp', 'limit': 10})
    except ApiError:
        return ''
    head = caption.strip()[:80]
    for row in res.get('data', []):
        if head and str(row.get('caption') or '').strip().startswith(head):
            return str(row.get('id') or '')
    return ''


# ─── GitHub: перевалка, откуда Instagram забирает ролик ──────────────────

def github_cfg(ctx, acc):
    g = dict(ctx.cfg.get('github') or {})
    g.update(acc.get('github') or {})
    g.setdefault('branch', 'main')
    g['dir'] = str(acc.get('github_dir') or g.get('dir') or '').strip('/')
    for key in ('token', 'owner', 'repo'):
        if not str(g.get(key) or '').strip() or str(g[key]).startswith('ВСТАВЬТЕ'):
            raise ApiError('в config.json не заполнено github.%s' % key)
    return g


def gh_headers(g):
    return {'Authorization': 'Bearer %s' % g['token'], 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'ig-server-publisher', 'Content-Type': 'application/json'}


def gh_url(ctx, g, name):
    inside = '/'.join([p for p in (g['dir'], name) if p])
    return '%s/repos/%s/%s/contents/%s' % (ctx.github_api, urllib.parse.quote(g['owner']), urllib.parse.quote(g['repo']),
                                          '/'.join(urllib.parse.quote(part) for part in inside.split('/')))


def describe_gh_error(status, raw):
    try:
        text = re.sub(r'\s+', ' ', str(json.loads(raw.decode('utf-8', 'replace')).get('message') or ''))[:200]
    except ValueError:
        text = ''
    if status == 401:
        return 'GitHub не принял токен — он истёк, отозван или скопирован не целиком. Выпустите новый и вставьте в config.json.'
    if status == 403:
        return 'GitHub отказал: %s' % (text or 'у токена нет права записи в репозиторий')
    if status == 404:
        return 'GitHub не нашёл репозиторий или ветку — проверьте github.owner, github.repo, github.branch'
    if status == 422:
        return 'GitHub не принял файл: %s' % (text or 'возможно, такой уже есть')
    return 'GitHub ответил %s%s' % (status, (': ' + text) if text else '')


def remote_name(attempt, ext):
    stamp = to_base36(int(time.time() * 1000))
    rnd = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for _ in range(8))
    return 'ig-%s-%s%s%s' % (stamp, rnd, ('-%d' % attempt) if attempt else '', ext)


def gh_upload(ctx, g, data, ext):
    """Кладёт файл в репозиторий. Имя на каждую попытку своё: повторный PUT тем же именем потребовал бы sha."""
    last = None
    for attempt in range(UPLOAD_ATTEMPTS):
        name = remote_name(attempt, ext)
        body = json.dumps({'message': 'картинка для публикации в Instagram (%s)' % name,
                           'content': base64.b64encode(data).decode('ascii'), 'branch': g['branch']}).encode('utf-8')
        try:
            status, _, raw = http(ctx, 'github', 'PUT', gh_url(ctx, g, name), headers=gh_headers(g), data=body, timeout=180)
        except ApiError as error:
            last = error
        else:
            if status in (200, 201):
                sha = str((json.loads(raw.decode('utf-8', 'replace')).get('content') or {}).get('sha') or '')
                return {'name': name, 'sha': sha,
                        'url': '%s/%s/%s/%s/%s' % (ctx.github_raw, g['owner'], g['repo'], g['branch'],
                                                   '/'.join(urllib.parse.quote(p) for p in [x for x in (g['dir'], name) if x]))}
            last = ApiError(describe_gh_error(status, raw), status=status, retry=(status in (400, 408, 409, 429) or status >= 500))
            if not last.retry:
                raise last
        if attempt + 1 < UPLOAD_ATTEMPTS:
            ctx.log('загрузка на GitHub не удалась (%s) — пробую ещё раз' % str(last)[:100])
            ctx.sleep(3 * (attempt + 1))
    raise last


def gh_delete(ctx, g, name, sha):
    if not sha:
        return False
    body = json.dumps({'message': 'картинка опубликована, файл больше не нужен (%s)' % name, 'sha': sha, 'branch': g['branch']}).encode('utf-8')
    try:
        status, _, _ = http(ctx, 'github', 'DELETE', gh_url(ctx, g, name), headers=gh_headers(g), data=body, timeout=30)
    except ApiError:
        return False
    return status in (200, 204, 404)


def cleanup(ctx, acc, st):
    """Недоудалённое (связь пропала в момент уборки) и забытое старше суток."""
    try:
        g = github_cfg(ctx, acc)
    except ApiError:
        return
    left = []
    for rec in st['pending_delete']:
        if not gh_delete(ctx, g, rec['name'], rec['sha']):
            left.append(rec)
    st['pending_delete'] = left
    last = parse_iso(st.get('swept_at'))
    if last and ctx.now() - last < timedelta(hours=6):
        return
    st['swept_at'] = ctx.now().isoformat()
    try:
        url = '%s/repos/%s/%s/contents/%s?ref=%s' % (ctx.github_api, urllib.parse.quote(g['owner']), urllib.parse.quote(g['repo']),
                                                      urllib.parse.quote(g['dir']), urllib.parse.quote(g['branch']))
        status, _, raw = http(ctx, 'github', 'GET', url, headers=gh_headers(g), timeout=30)
        rows = json.loads(raw.decode('utf-8', 'replace')) if status == 200 else []
    except (ApiError, ValueError):
        return
    for row in rows if isinstance(rows, list) else []:
        m = FILE_NAME.match(str(row.get('name') or ''))
        if not m:
            continue            # чужие файлы не трогаем: только то, что назвала сама программа
        try:
            made = int(m.group(1), 36) / 1000.0
        except ValueError:
            continue
        if time.time() - made > 24 * 3600:
            gh_delete(ctx, g, row['name'], row.get('sha'))


def check_video_url(ctx, url):
    """Instagram пойдёт за файлом сам, поэтому смотрим на него глазами Instagram: начало файла и заголовки."""
    try:
        status, headers, raw = http(ctx, 'github', 'GET', url, headers={'Range': 'bytes=0-1023'}, timeout=30)
    except ApiError as error:
        raise ApiError('ролик не открывается по адресу %s (%s)' % (url, error))
    if status not in (200, 206):
        raise ApiError('по адресу %s сервер отвечает %s' % (url, status), retry=True)
    ctype = str(headers.get('Content-Type') or '').lower()
    looks_mp4 = len(raw) >= 12 and raw[4:8] == b'ftyp'
    if not (ctype.startswith('video/') or looks_mp4):
        raise ApiError('по адресу %s лежит не видео (тип «%s»)' % (url, ctype or '?'))


# ─── публикация ─────────────────────────────────────────────────────────

def add_run(st, slot_id, now, ok, note='', media_id='', uncertain=False, name=''):
    rec = {'slotId': slot_id, 'at': now.isoformat(), 'format': 'reels', 'ok': bool(ok), 'note': note[:300],
           'mediaId': media_id, 'name': name}
    if uncertain:
        rec['uncertain'] = True
    st['history'] = ([rec] + st['history'])[:MAX_HISTORY]


def publish_next(ctx, acc, slot_id):
    """Выкладывает следующий ролик. Возвращает (ok, текст). Всё записывает в состояние."""
    name = acc['name']
    st = ctx.acc_state(name)
    now = ctx.now()
    item = None
    uploaded = None
    g = None
    try:
        queue = read_queue(acc, st)
        if queue['error']:
            raise ApiError('Готовые видео: %s' % queue['error'])
        item = queue['next']
        if not item:
            raise ApiError('Все видео из папки уже опубликованы — положите в неё новые.')
        caption = read_caption(item)
        problem = video_problem(item, caption)
        if problem:
            raise ApiError('Готовые видео: %s' % problem)
        g = github_cfg(ctx, acc)
        token = ensure_token(ctx, acc, st)
        cleanup(ctx, acc, st)
        # Суточный предел самого Instagram главнее нашего. Нет связи или токен не принят — выясняем ДО загрузки на GitHub.
        used = total = 0
        try:
            lim = api(ctx, 'GET', 'me/content_publishing_limit', token, {'fields': 'config,quota_usage'})
            row = (lim.get('data') or [{}])[0]
            used, total = int(row.get('quota_usage') or 0), int((row.get('config') or {}).get('quota_total') or 0)
        except ApiError as error:
            if not error.definite or error.code == 190 or error.status == 401:
                raise
        if total and used >= total:
            raise ApiError('Instagram принял %d публикаций из %d за сутки — следующая будет позже.' % (used, total))
        twin = already_posted(ctx, token, caption)
        if twin:
            st['published'][item['name']] = {'at': now.isoformat(), 'mediaId': twin}
            add_run(st, slot_id, now, True, 'такой пост уже есть в ленте — повторно не публикуем', twin, name=item['name'])
            ctx.save()
            return True, '«%s» уже в ленте (id %s) — отмечен вышедшим, дубль не создан' % (item['name'], twin)
        left_before = len([i for i in queue['items'] if not i['published']])
        ctx.log('[%s] публикую «%s» (в очереди %d)' % (name, item['name'], left_before))
        with open(item['path'], 'rb') as fh:
            data = fh.read()
        ctx.log('[%s] загружаю на GitHub (%.1f МБ)' % (name, len(data) / 1048576.0))
        uploaded = gh_upload(ctx, g, data, os.path.splitext(item['name'])[1].lower())
        check_video_url(ctx, uploaded['url'])
        ctx.log('[%s] передаю Instagram ссылку на ролик' % name)
        container = api(ctx, 'POST', 'me/media', token,
                        {'media_type': 'REELS', 'video_url': uploaded['url'], 'caption': caption, 'share_to_feed': 'true'}, timeout=90).get('id')
        if not container:
            raise ApiError('Instagram не завёл контейнер для Reels.')
        deadline = time.time() + REEL_WAIT_SEC
        while True:
            status = api(ctx, 'GET', container, token, {'fields': 'status_code,status'})
            code = str(status.get('status_code') or '')
            if code == 'FINISHED':
                break
            if code in ('ERROR', 'EXPIRED'):
                raise ApiError('Instagram не смог обработать ролик (%s): %s' % (code, str(status.get('status') or '')[:160]))
            if time.time() > deadline:
                raise ApiError('Instagram не закончил обработку ролика за %d минут.' % (REEL_WAIT_SEC // 60))
            ctx.sleep(POLL_SEC)
        # ⚠️ Публикацию контейнера повторять после обрыва нельзя: пост мог уже выйти.
        try:
            media_id = api(ctx, 'POST', 'me/media_publish', token, {'creation_id': container}, timeout=90).get('id') or ''
        except ApiError as error:
            if error.definite:
                raise
            add_run(st, slot_id, now, False, 'публикация оборвалась на последнем шаге, исход неизвестен: %s' % error,
                    uncertain=True, name=item['name'])
            # Полчаса аккаунт не трогаем. Потом заход сверит ленту: вышел — отметит, не вышел — выложит заново.
            st['hold_until'] = (now + timedelta(minutes=HOLD_AFTER_UNCERTAIN_MIN)).isoformat()
            ctx.save()
            text = ('«%s»: связь оборвалась на последнем шаге — проверьте ленту Instagram вручную. '
                    'Эту публикацию повторно не отправляю. Через %d минут сверю ленту: если ролик там — отмечу вышедшим, '
                    'если нет — выложу заново.' % (item['name'], HOLD_AFTER_UNCERTAIN_MIN))
            ctx.log('[%s] %s' % (name, text))
            ctx.notify('⚠️ Instagram «%s»: %s' % (name, text))
            return False, text
        st['published'][item['name']] = {'at': ctx.now().isoformat(), 'mediaId': media_id}
        add_run(st, slot_id, now, True, '', media_id, name=item['name'])
        ctx.save()
        text = '«%s» опубликован (id %s). В очереди осталось: %d.' % (item['name'], media_id, left_before - 1)
        ctx.log('[%s] %s' % (name, text))
        ctx.notify('✅ Instagram «%s»: %s' % (name, text))
        return True, text
    except ApiError as error:
        add_run(st, slot_id, now, False, str(error), name=(item['name'] if item else ''))
        ctx.save()
        tries = len(slot_attempts(st['history'], slot_id, now, ctx.tz))
        tail = (' Повтор через %d минут (попытка %d из %d).' % (REPEAT_AFTER_MIN, tries, ATTEMPTS_PER_DAY)) if tries < ATTEMPTS_PER_DAY else ' Попытки на сегодня закончились.'
        text = ('«%s»: ' % item['name'] if item else '') + str(error) + tail
        ctx.log('[%s] не вышло — %s' % (name, text))
        ctx.notify('❌ Instagram «%s»: не вышло — %s' % (name, text))
        return False, text
    finally:
        # Файл на GitHub нужен только на время публикации. Не удалился — запомним и удалим в следующий заход.
        if uploaded and g:
            if not gh_delete(ctx, g, uploaded['name'], uploaded['sha']):
                st['pending_delete'].append({'name': uploaded['name'], 'sha': uploaded['sha']})
                ctx.save()


def run_once(ctx):
    for acc in ctx.cfg.get('accounts', []):
        if acc.get('enabled', True) is False:
            continue
        st = ctx.acc_state(acc['name'])
        hold = parse_iso(st.get('hold_until'))
        if hold and ctx.now() < hold:
            continue                       # исход прошлой публикации неизвестен: ждём, пока пост появится в ленте или станет ясно, что его нет
        slot, _ = due_slot(acc, st['history'], ctx.now(), ctx.tz, ctx.installed_at())
        if slot is None:
            if st['pending_delete']:
                cleanup(ctx, acc, st)
                ctx.save()
            continue
        publish_next(ctx, acc, slot['id'])


# ─── блокировка, чтобы заходы не наступали друг другу на пятки ─────────────

class Lock(object):
    def __init__(self, path):
        self.path, self.held = path, False

    def __enter__(self):
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if time.time() - os.path.getmtime(self.path) < LOCK_STALE_SEC:
                return self
            os.remove(self.path)
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        self.held = True
        return self

    def __exit__(self, *exc):
        if self.held:
            try:
                os.remove(self.path)
            except OSError:
                pass


# ─── команды ────────────────────────────────────────────────────────────

def cmd_status(ctx):
    now = ctx.now()
    print('Сейчас на сервере: %s (UTC%+g)' % (now.strftime('%Y-%m-%d %H:%M'), float(ctx.cfg.get('utc_offset_hours', 3))))
    for acc in ctx.cfg.get('accounts', []):
        st = ctx.acc_state(acc['name'])
        queue = read_queue(acc, st)
        print('\n== %s %s' % (acc['name'], '' if acc.get('enabled', True) else '(выключен)'))
        if queue['error']:
            print('  Очередь: %s' % queue['error'])
        else:
            left = [i for i in queue['items'] if not i['published']]
            print('  Очередь: осталось %d из %d; следующий: %s' % (len(left), len(queue['items']), queue['next']['name'] if queue['next'] else '—'))
            for i in queue['items']:
                print('   - %-28s %5.1f МБ  %s' % (i['name'], i['size'] / 1048576.0, 'вышел' if i['published'] else ('ждёт' if i['has_caption'] else 'НЕТ ПОДПИСИ (.txt)')))
        hold = parse_iso(st.get('hold_until'))
        if hold and now < hold:
            print('  ⚠️ Исход прошлой публикации неизвестен, аккаунт на паузе до %s (проверьте ленту Instagram)' % hold.astimezone(ctx.tz).strftime('%H:%M'))
        slot, why = due_slot(acc, st['history'], now, ctx.tz, ctx.installed_at())
        print('  Сейчас: %s' % (('пора публиковать (слот %s)' % slot['id']) if slot else why))
        print('  Ближайшие выходы:')
        for at, _ in next_runs(acc, now):
            print('   - %s' % at.strftime('%a %d.%m %H:%M'))
        print('  Последние попытки:')
        for rec in st['history'][:5]:
            at = parse_iso(rec['at'])
            print('   - %s  %s  %s' % (at.astimezone(ctx.tz).strftime('%d.%m %H:%M') if at else rec['at'],
                                      'вышло' if rec['ok'] else ('НЕИЗВЕСТНО' if rec.get('uncertain') else 'не вышло'),
                                      rec.get('note') or rec.get('name') or ''))
        if not st['history']:
            print('   - пока ничего')
        if st['pending_delete']:
            print('  Ждут удаления с GitHub: %d' % len(st['pending_delete']))


def reach(ctx, kind, url, label):
    t = time.time()
    try:
        status, _, _ = http(ctx, kind, 'GET', url, timeout=20)
        print('  %-28s доступен (HTTP %s, %.1f с)' % (label, status, time.time() - t))
        return True
    except ApiError as error:
        print('  %-28s НЕ ДОСТУПЕН: %s' % (label, error))
        return False


def cmd_check(ctx):
    bad = 0
    print('Доступность адресов с этого сервера%s:' % (' (Instagram — через прокси)' if str(ctx.cfg.get('proxy') or '').strip() else ''))
    if not reach(ctx, 'instagram', ctx.api_host + '/', 'Instagram API'):
        bad += 1
        print('    → из России он может быть закрыт. Нужен прокси (поле proxy в config.json) или запуск за границей.')
    if not reach(ctx, 'github', ctx.github_api + '/', 'GitHub API'):
        bad += 1
    if not reach(ctx, 'github', ctx.github_raw + '/', 'GitHub raw (отсюда берёт Instagram)'):
        bad += 1
    for acc in ctx.cfg.get('accounts', []):
        st = ctx.acc_state(acc['name'])
        print('\n== %s' % acc['name'])
        try:
            token = ensure_token(ctx, acc, st)
            me = api(ctx, 'GET', 'me', token, {'fields': 'username,account_type'})
            print('  токен Instagram принят: @%s (%s)' % (me.get('username'), me.get('account_type')))
        except ApiError as error:
            print('  ТОКЕН INSTAGRAM: %s' % error)
            bad += 1
        try:
            g = github_cfg(ctx, acc)
            status, _, raw = http(ctx, 'github', 'GET', '%s/repos/%s/%s' % (ctx.github_api, g['owner'], g['repo']), headers=gh_headers(g), timeout=30)
            if status == 200 and (json.loads(raw.decode('utf-8', 'replace')).get('permissions') or {}).get('push') is not False:
                print('  GitHub: репозиторий %s/%s доступен, запись разрешена' % (g['owner'], g['repo']))
            else:
                print('  GITHUB: %s' % describe_gh_error(status, raw))
                bad += 1
        except ApiError as error:
            print('  GITHUB: %s' % error)
            bad += 1
        queue = read_queue(acc, st)
        if queue['error'] or not queue['next']:
            print('  ОЧЕРЕДЬ: %s' % (queue['error'] or 'нет ролика к публикации'))
            bad += 1
            continue
        problem = video_problem(queue['next'], read_caption(queue['next']))
        print('  следующий ролик: %s%s' % (queue['next']['name'], (' — ПРОБЛЕМА: ' + problem) if problem else ' (подпись есть)'))
        bad += 1 if problem else 0
    print('\nИтог: %s' % ('всё в порядке' if not bad else 'есть что исправить (%d)' % bad))
    return 1 if bad else 0


def cmd_fetch_inbox(ctx, acc, folder):
    """Скачивает ролики и подписи из папки репозитория на GitHub в videos_dir аккаунта.
    Нужно, когда с компьютера слать долго: файлы кладут на GitHub быстрым каналом, сервер забирает их оттуда."""
    g = dict(ctx.cfg.get('github') or {})
    g.update(acc.get('github') or {})
    owner, repo, branch = str(g.get('owner') or ''), str(g.get('repo') or ''), str(g.get('branch') or 'main')
    if not owner or not repo or owner.startswith('ВСТАВЬТЕ') or repo.startswith('ВСТАВЬТЕ'):
        raise SystemExit('В config.json не заполнено github.owner / github.repo')
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'ig-server-publisher'}
    token = str(g.get('token') or '').strip()
    if token and not token.startswith('ВСТАВЬТЕ'):
        headers['Authorization'] = 'Bearer %s' % token
    url = '%s/repos/%s/%s/contents/%s?ref=%s' % (ctx.github_api, urllib.parse.quote(owner), urllib.parse.quote(repo),
                                                  urllib.parse.quote(folder), urllib.parse.quote(branch))
    try:
        status, _, raw = http(ctx, 'github', 'GET', url, headers=headers, timeout=60)
    except ApiError as error:
        print('Не удалось открыть GitHub: %s' % error)
        return 1
    if status != 200:
        print('GitHub: папка «%s» не открылась (%s)' % (folder, describe_gh_error(status, raw)))
        return 1
    rows = [r for r in json.loads(raw.decode('utf-8', 'replace')) if r.get('type') == 'file'
            and str(r.get('name') or '').lower().endswith(VIDEO_EXT + ('.txt',))]
    if not rows:
        print('В папке «%s» нет роликов (.mp4/.mov) и подписей (.txt).' % folder)
        return 1
    dest_dir = acc['videos_dir']
    os.makedirs(dest_dir, exist_ok=True)
    got = skipped = failed = 0
    for row in sorted(rows, key=lambda r: natural_key(r['name'])):
        name, size = row['name'], int(row.get('size') or 0)
        dest = os.path.join(dest_dir, name)
        if os.path.exists(dest) and os.path.getsize(dest) == size:
            skipped += 1
            continue
        file_url = '%s/%s/%s/%s/%s/%s' % (ctx.github_raw, owner, repo, branch, '/'.join(urllib.parse.quote(p) for p in folder.split('/')),
                                          urllib.parse.quote(name))
        part = dest + '.part'
        try:
            req = urllib.request.Request(file_url, headers={'User-Agent': 'ig-server-publisher'})
            with ctx.opener('github').open(req, timeout=120) as resp, open(part, 'wb') as out:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
            if size and os.path.getsize(part) != size:
                raise OSError('размер %d вместо %d' % (os.path.getsize(part), size))
            os.replace(part, dest)
            got += 1
            print('  скачан %-28s %6.1f МБ' % (name, size / 1048576.0))
        except Exception as error:  # noqa: BLE001
            failed += 1
            print('  НЕ СКАЧАН %s: %s' % (name, str(error)[:120]))
            try:
                os.remove(part)
            except OSError:
                pass
    print('Готово: скачано %d, уже было %d, ошибок %d. Папка: %s' % (got, skipped, failed, dest_dir))
    return 1 if failed else 0


def find_account(ctx, name):
    accounts = ctx.cfg.get('accounts', [])
    if name:
        for acc in accounts:
            if acc['name'] == name:
                return acc
        raise SystemExit('Аккаунт «%s» не найден в config.json' % name)
    if len(accounts) == 1:
        return accounts[0]
    raise SystemExit('Укажите аккаунт: --account ИМЯ')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Серверный публикатор Reels для Instagram')
    parser.add_argument('command', nargs='?', default='run', choices=['run', 'status', 'check', 'publish-now', 'mark-published', 'forget', 'fetch-inbox'])
    parser.add_argument('target', nargs='*')
    parser.add_argument('--account', default='')
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--from', dest='inbox', default='inbox')
    parser.add_argument('--dir', default=HERE)
    args = parser.parse_args(argv)
    # Консоль Windows и планировщик читают вывод в 1251/866: эмодзи и кавычки без этого роняют печать.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, ValueError):
            pass
    ctx = Ctx(args.dir)

    if args.command == 'status':
        cmd_status(ctx)
        return 0
    if args.command == 'check':
        return cmd_check(ctx)
    if args.command == 'fetch-inbox':
        return cmd_fetch_inbox(ctx, find_account(ctx, args.target[0] if args.target else args.account), args.inbox)
    if args.command == 'publish-now':
        if not args.yes:
            raise SystemExit('Это настоящая публикация. Добавьте --yes: ig_publisher.py publish-now АККАУНТ --yes')
        acc = find_account(ctx, args.target[0] if args.target else args.account)
        with Lock(os.path.join(ctx.dir, 'run.lock')) as lock:
            if not lock.held:
                raise SystemExit('Сейчас идёт другой заход (run.lock). Подождите несколько минут.')
            ok, text = publish_next(ctx, acc, 'manual')
        print(text)
        return 0 if ok else 1
    if args.command in ('mark-published', 'forget'):
        acc = find_account(ctx, args.account)
        st = ctx.acc_state(acc['name'])
        for n in args.target:
            if args.command == 'mark-published':
                st['published'][n] = {'at': ctx.now().isoformat(), 'mediaId': ''}
            else:
                st['published'].pop(n, None)
                if n in acc.get('already_published', []):
                    print('«%s» перечислен в already_published в config.json — удалите его оттуда тоже.' % n)
        ctx.save()
        print('Готово.')
        return 0

    with Lock(os.path.join(ctx.dir, 'run.lock')) as lock:
        if not lock.held:
            return 0                                  # прошлый заход ещё идёт
        run_once(ctx)
    return 0


if __name__ == '__main__':
    sys.exit(main())
