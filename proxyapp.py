"""Proxy Checker (Android / Kivy) - stdlib + kivy + certifi only (fewer things that can fail on a phone)."""
import queue
import re
import socket
import ssl
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.factory import Factory
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.utils import get_color_from_hex

PORT = "3128"
UA = {"User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36"}

KV = """
#:import hex kivy.utils.get_color_from_hex
<Pill@Button>:
    background_normal: ''
    background_down: ''
    background_color: 0, 0, 0, 0
    color: 1, 1, 1, 1
    bold: True
    font_size: '15sp'
    bg: hex('#4F46E5')
    canvas.before:
        Color:
            rgba: self.bg if self.state == 'normal' else (self.bg[0] * 0.8, self.bg[1] * 0.8, self.bg[2] * 0.8, 1)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]

<Stat@BoxLayout>:
    title: ''
    value: '0'
    tint: hex('#4F46E5')
    orientation: 'vertical'
    padding: dp(6)
    canvas.before:
        Color:
            rgba: 1, 1, 1, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]
    Label:
        text: root.value
        color: root.tint
        bold: True
        font_size: '24sp'
    Label:
        text: root.title
        color: hex('#6B7280')
        font_size: '12sp'

BoxLayout:
    orientation: 'vertical'
    padding: dp(16)
    spacing: dp(10)
    Label:
        text: 'Proxy Checker'
        color: hex('#1F2937')
        bold: True
        font_size: '26sp'
        size_hint_y: None
        height: dp(44)
        halign: 'left'
        text_size: self.size
    Label:
        text: 'freeproxy.world  -  port 3128'
        color: hex('#6B7280')
        font_size: '13sp'
        size_hint_y: None
        height: dp(18)
        halign: 'left'
        text_size: self.size
    BoxLayout:
        size_hint_y: None
        height: dp(76)
        spacing: dp(8)
        Stat:
            id: s_found
            title: 'Found'
        Stat:
            id: s_tested
            title: 'Tested'
            tint: hex('#D97706')
        Stat:
            id: s_ok
            title: 'Working'
            tint: hex('#16A34A')
    ProgressBar:
        id: bar
        max: 1
        size_hint_y: None
        height: dp(8)
    Label:
        id: status
        text: 'Ready.'
        color: hex('#6B7280')
        font_size: '12sp'
        size_hint_y: None
        height: dp(34)
        halign: 'left'
        valign: 'middle'
        text_size: self.size
    BoxLayout:
        size_hint_y: None
        height: dp(50)
        spacing: dp(8)
        Pill:
            text: 'Fetch & Test'
            on_release: app.start()
        Pill:
            text: 'Stop'
            bg: hex('#DC2626')
            on_release: app.stop_run()
    BoxLayout:
        size_hint_y: None
        height: dp(50)
        spacing: dp(8)
        Pill:
            text: 'Copy fastest'
            bg: hex('#16A34A')
            on_release: app.copy_best()
        Pill:
            text: 'Wi-Fi settings'
            bg: hex('#374151')
            on_release: app.open_wifi()
    Pill:
        text: 'How to connect (Samsung)'
        bg: hex('#7C3AED')
        size_hint_y: None
        height: dp(50)
        on_release: app.show_help()
    Label:
        text: 'Tap a working proxy to copy its IP address'
        color: hex('#6B7280')
        font_size: '12sp'
        size_hint_y: None
        height: dp(20)
    ScrollView:
        GridLayout:
            id: lst
            cols: 1
            size_hint_y: None
            height: self.minimum_height
            spacing: dp(6)
"""


# ------------------------------------------------------------------ networking (stdlib only)
def make_ctx():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def valid_ip(ip):
    return all(0 <= int(x) <= 255 for x in ip.split("."))


def parse_proxies(text, want_port=PORT):
    found = []
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})", text):
        if valid_ip(m.group(1)) and m.group(2) == want_port:
            found.append("%s:%s" % (m.group(1), m.group(2)))
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})", text):          # html table: ip ... port
        pm = re.search(r">\s*(\d{2,5})\s*<", text[m.end(): m.end() + 400])
        if pm and valid_ip(m.group(1)) and pm.group(1) == want_port:
            found.append("%s:%s" % (m.group(1), pm.group(1)))
    return list(dict.fromkeys(found))


def fetch_page(ctx, page):
    url = ("https://www.freeproxy.world/?type=&anonymity=&country=&speed=&port=%s&page=%d" % (PORT, page))
    req = urllib.request.Request(url, headers=UA)
    html = urllib.request.urlopen(req, timeout=20, context=ctx).read().decode("utf-8", "ignore")
    return parse_proxies(html)


def probe(addr, ctx, timeout=8):
    """CONNECT through the proxy to gstatic over TLS (checks the certificate) -> latency ms or None."""
    ip, port = addr.rsplit(":", 1)
    t = time.time()
    s = None
    try:
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"CONNECT www.gstatic.com:443 HTTP/1.1\r\nHost: www.gstatic.com:443\r\n\r\n")
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 8192:
            d = s.recv(4096)
            if not d:
                break
            head += d
        if b" 200" not in head.split(b"\r\n", 1)[0]:
            return None
        with ctx.wrap_socket(s, server_hostname="www.gstatic.com") as tls:
            s = None
            tls.sendall(b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n")
            if b" 204" not in tls.recv(200).split(b"\r\n", 1)[0]:
                return None
        return int((time.time() - t) * 1000)
    except Exception:
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


class ProxyApp(App):
    title = "Proxy Checker"

    def build(self):
        Window.clearcolor = get_color_from_hex("#F4F6FB")
        self.q, self.stop, self.running = queue.Queue(), threading.Event(), False
        self.c = {"found": 0, "tested": 0, "ok": 0}
        self.speeds = {}
        self.ui = Builder.load_string(KV)
        Clock.schedule_interval(self.poll, 0.2)
        return self.ui

    # ---- actions
    def start(self):
        if self.running:
            return
        self.ui.ids.lst.clear_widgets()
        self.c = dict.fromkeys(self.c, 0)
        self.speeds.clear()
        self.ui.ids.bar.value = 0
        self.stop.clear()
        self.running = True
        threading.Thread(target=self.worker, daemon=True).start()

    def stop_run(self):
        self.stop.set()
        self.say("Stopping...")

    def say(self, t):
        self.ui.ids.status.text = t

    def copy_best(self):
        if not self.speeds:
            return self.say("No working proxy yet.")
        best = min(self.speeds, key=self.speeds.get)
        Clipboard.copy(best.split(":")[0])
        self.say("Copied IP %s - use Port %s. Tap 'How to connect'." % (best.split(":")[0], PORT))

    def show_help(self):
        from kivy.uix.label import Label
        from kivy.uix.popup import Popup
        text = (
            "WI-FI (Samsung One UI)\n"
            "1. Settings > Connections > Wi-Fi\n"
            "2. Tap the gear next to your network\n"
            "3. Scroll down: View more > Proxy > Manual\n"
            "4. Host = the copied IP, Port = 3128 > Save\n\n"
            "MOBILE DATA\n"
            "Settings > Connections > Mobile networks >\n"
            "Access point names > your APN > Proxy and Port\n"
            "(not every app follows this setting)\n\n"
            "WHEN FINISHED set Proxy back to None.\n"
            "Free proxies are not private: do not sign in to banks or important accounts."
        )
        lab = Label(text=text, font_size="14sp", halign="left", valign="top")
        lab.bind(size=lambda w, sz: setattr(w, "text_size", (sz[0] - dp(12), None)))
        Popup(title="How to connect", content=lab, size_hint=(0.94, 0.78)).open()

    def open_wifi(self):
        try:
            from jnius import autoclass
            Intent = autoclass("android.content.Intent")
            Settings = autoclass("android.provider.Settings")
            act = autoclass("org.kivy.android.PythonActivity").mActivity
            act.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS))
        except Exception:
            self.say("Open Settings > Wi-Fi manually.")

    # ---- background
    def worker(self):
        try:
            ctx = make_ctx()
            items, pages = [], 3                      # Galaxy A24 (4 GB RAM): keep it light
            for p in range(1, pages + 1):
                if self.stop.is_set():
                    break
                self.q.put(("s", "Fetching page %d/%d..." % (p, pages)))
                try:
                    rows = fetch_page(ctx, p)
                except Exception as e:
                    self.q.put(("s", "Fetch failed: %s" % str(e)[:80]))
                    break
                if not rows:
                    break
                for a in rows:
                    if a not in items:
                        items.append(a)
                        self.q.put(("add",))
            if items and not self.stop.is_set():
                items = items[:150]
                self.q.put(("s", "Testing %d proxies..." % len(items)))
                with ThreadPoolExecutor(max_workers=24) as ex:
                    futs = {ex.submit(self.guard, a, ctx): a for a in items}
                    for f in as_completed(futs):
                        r = f.result()
                        if r != "skip":
                            self.q.put(("res", futs[f], r, len(items)))
                    ex.shutdown(cancel_futures=True)
        except Exception as e:
            self.q.put(("s", "Error: %s" % str(e)[:100]))
        finally:
            self.q.put(("done",))

    def guard(self, addr, ctx):
        return "skip" if self.stop.is_set() else probe(addr, ctx)

    # ---- UI updates (main thread only)
    def poll(self, dt):
        for _ in range(100):
            try:
                m = self.q.get_nowait()
            except queue.Empty:
                break
            if m[0] == "s":
                self.say(m[1])
            elif m[0] == "add":
                self.c["found"] += 1
            elif m[0] == "res":
                _, key, ms, total = m
                self.c["tested"] += 1
                self.ui.ids.bar.value = self.c["tested"] / max(total, 1)
                if ms is not None:
                    self.c["ok"] += 1
                    self.speeds[key] = ms
                    b = Factory.Pill(text="%s   -   %d ms" % (key, ms), size_hint_y=None, height=dp(48),
                                     bg=get_color_from_hex("#16A34A"))
                    b.bind(on_release=lambda w, k=key: (Clipboard.copy(k.split(":")[0]),
                                                        self.say("Copied IP %s - Port is %s" % (k.split(":")[0], PORT))))
                    self.ui.ids.lst.add_widget(b, index=len(self.ui.ids.lst.children))
            elif m[0] == "done":
                self.running = False
                self.say("Finished - %d working of %d" % (self.c["ok"], self.c["found"]))
        i = self.ui.ids
        i.s_found.value = str(self.c["found"])
        i.s_tested.value = str(self.c["tested"])
        i.s_ok.value = str(self.c["ok"])
