#!/usr/bin/env python3
"""
Mihomo Hub & Subscription Converter for Android
"""
from __future__ import annotations

import base64
import copy
import gzip
import json
import os
import re
import sys
import threading
import uuid as _uuid
import zlib
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlparse, urlencode
import urllib.request
import urllib.error

# Поддержка работы в изолированном хранилище Android
DATA_DIR = os.environ.get("ANDROID_PRIVATE") or os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(DATA_DIR, "subscriptions.json")
CUSTOM_RULES_FILE = os.path.join(DATA_DIR, "custom_routing.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
PORT = 12096

try:
    import yaml
except ImportError:
    # Запасной вариант на случай отсутствия C-библиотек
    yaml = None

CLIENT_PRESETS = {
    "1": ("FlClash X (Windows)", "FlClash X/v0.3.2 Platform/windows", {"x-device-os": "Windows", "x-device-model": "Windows 11 Pro", "x-ver-os": "25H2", "accept-encoding": "gzip"}),
    "2": ("Throne (Windows)", "Throne/1.1.2", {"x-device-os": "Windows", "x-device-model": "H510M H", "x-ver-os": "10.0.26200", "accept-encoding": "gzip, deflate", "accept-language": "ru-RU,en,*"}),
    "3": ("Hiddify", "HiddifyNext/2.0.5 (linux; amd64)", {}),
    "4": ("v2rayNG", "v2rayNG/1.8.9", {}),
    "5": ("Happ (iOS)", "Happ/1.4.2 CFNetwork/1494.0.7 Darwin/23.4.0", {}),
    "6": ("sing-box", "sing-box/1.8.6 (linux; amd64)", {}),
    "7": ("Nekoray", "Nekoray/3.26 (linux; amd64)", {}),
}

PROTO_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "wireguard://", "wg://")

DEFAULT_SETTINGS = {
    "warp_chain": {
        "enabled": True,
        "server": "engage.cloudflareclient.com",
        "port": 2408,
        "ip": "172.16.0.2",
        "ipv6": "2606:4700:110:83ab:1a5c:94d4:8a14:87f7",
        "private-key": "yA2Yu/uN7U4miC6Z8sYsWKnRjitK4OBtyfL4W8szJUY=",
        "public-key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "reserved": [117, 169, 145],
        "udp": True,
        "remote-dns-resolve": True
    }
}

def load_settings() -> dict:
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "warp_chain" not in data:
                    data["warp_chain"] = DEFAULT_SETTINGS["warp_chain"]
                return data
        except Exception:
            return DEFAULT_SETTINGS
    save_settings(DEFAULT_SETTINGS)
    return DEFAULT_SETTINGS

def save_settings(st: dict):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(st, f, indent=2, ensure_ascii=False)

def load_custom_routing() -> dict:
    if os.path.exists(CUSTOM_RULES_FILE):
        with open(CUSTOM_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for g in data.get("groups", []):
                if "proto" not in g:
                    g["proto"] = "all"
            return data
            
    default_routing = {
        "groups": [
            {
                "name": "🎮 Игры и Стим",
                "processes": ["RobloxPlayerBeta.exe", "javaw.exe", "steam.exe"],
                "domains": ["steamcommunity.com", "steampowered.com", "roblox.com"],
                "proto": "all"
            },
            {
                "name": "🎧 Музыка",
                "processes": ["Spotify.exe"],
                "domains": ["spotify.com", "scdn.co"],
                "proto": "all"
            }
        ]
    }
    with open(CUSTOM_RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(default_routing, f, indent=2, ensure_ascii=False)
    return default_routing

def save_custom_routing(data: dict):
    with open(CUSTOM_RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def default_rule_providers() -> Dict[str, dict]:
    return {
        "geosite-private": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.mrs", "path": "./rule-sets/geosite-private.mrs"},
        "ai": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ai-!cn.mrs", "path": "./rule-sets/ai.mrs"},
        "category-porn": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-porn.mrs", "path": "./rule-sets/category-porn.mrs"},
        "geoip-for-ru": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "ipcidr", "format": "mrs", "url": "https://raw.githubusercontent.com/Davoyan/mihomo-rule-sets/main/ip-for-ru/lists/ips-for-ru.mrs", "path": "./rule-sets/geoip-for-ru.mrs"},
        "discord_domains": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/discord.mrs", "path": "./rule-sets/discord_domains.mrs"},
        "discord_voiceips": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "ipcidr", "format": "mrs", "url": "https://raw.githubusercontent.com/legiz-ru/mihomo-rule-sets/main/other/discord-voice-ip-list.mrs", "path": "./rule-sets/discord_voiceips.mrs"},
        "refilter_domains": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/legiz-ru/mihomo-rule-sets/main/re-filter/domain-rule.mrs", "path": "./rule-sets/refilter.mrs"},
        "youtube": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.mrs", "path": "./rule-sets/youtube.mrs"},
        "google-deepmind": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google-deepmind.mrs", "path": "./rule-sets/google-deepmind.mrs"},
        "telegram-ips": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "ipcidr", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.mrs", "path": "./rule-sets/telegram-ips.mrs"},
        "telegram-domains": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.mrs", "path": "./rule-sets/telegram-domains.mrs"},
        "additional-telegram-ips": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "classical", "format": "yaml", "url": "https://raw.githubusercontent.com/Davoyan/mihomo-rule-sets/main/domains/additional-telegram-ips.yaml", "path": "./rule-sets/additional-telegram-ips.yaml"},
        "additional-telegram-domains": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "classical", "format": "yaml", "url": "https://raw.githubusercontent.com/Davoyan/mihomo-rule-sets/main/domains/additional-telegram-domains.yaml", "path": "./rule-sets/additional-telegram-domains.yaml"},
        "geosite-ru": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/ru.mrs", "path": "./rule-sets/geosite-ru.mrs"},
        "speedtest-net": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/speedtest.mrs", "path": "./rule-sets/speedtest-net.mrs"},
        "oisd_big": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/legiz-ru/mihomo-rule-sets/main/oisd/big.mrs", "path": "./rule-sets/oisd_big.mrs"},
        "torrent-trackers": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/legiz-ru/mihomo-rule-sets/main/other/torrent-trackers.mrs", "path": "./rule-sets/torrent-trackers.mrs"},
        "torrent-clients": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "classical", "format": "yaml", "url": "https://raw.githubusercontent.com/legiz-ru/mihomo-rule-sets/main/other/torrent-clients.yaml", "path": "./rule-sets/torrent-clients.yaml"},
        "ru-apps": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "classical", "format": "yaml", "url": "https://raw.githubusercontent.com/legiz-ru/mihomo-rule-sets/main/other/ru-app-list.yaml", "path": "./rule-sets/ru-apps.yaml"},
        "ru-inside": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "classical", "format": "text", "url": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-clashx.lst", "path": "./rule-sets/ru-inside.lst"},
        "cloudflare-ips": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "ipcidr", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cloudflare.mrs", "path": "./rule-sets/cloudflare-ips.mrs"},
        "inline-blocked-ips": {"type": "inline", "payload": ["IP-CIDR,172.232.25.131/32"], "behavior": "classical"},
        "geoip-private": {"type": "inline", "payload": ["IP-CIDR,0.0.0.0/8","IP-CIDR,10.0.0.0/8","IP-CIDR,100.64.0.0/10","IP-CIDR,127.0.0.0/8","IP-CIDR,169.254.0.0/16","IP-CIDR,172.16.0.0/12","IP-CIDR,192.0.0.0/24","IP-CIDR,192.0.2.0/24","IP-CIDR,192.88.99.0/24","IP-CIDR,192.168.0.0/16","IP-CIDR,198.18.0.0/15","IP-CIDR,198.51.100.0/24","IP-CIDR,203.0.113.0/24","IP-CIDR,224.0.0.0/3","IP-CIDR,::/127","IP-CIDR,fc00::/7","IP-CIDR,fe80::/10","IP-CIDR,ff00::/8"], "behavior": "classical"},
        "ru-inline-banned": {"type": "inline", "payload": ["DOMAIN-SUFFIX,ua","DOMAIN-SUFFIX,habr.com","DOMAIN-SUFFIX,seasonvar.ru","DOMAIN-SUFFIX,lib.social","DOMAIN-SUFFIX,kemono.su","DOMAIN-SUFFIX,jut.su","DOMAIN-SUFFIX,kara.su","DOMAIN-SUFFIX,theins.ru","DOMAIN-SUFFIX,tvrain.ru","DOMAIN-SUFFIX,echo.msk.ru","DOMAIN-SUFFIX,the-village.ru","DOMAIN-SUFFIX,snob.ru","DOMAIN-SUFFIX,novayagazeta.ru","DOMAIN-SUFFIX,moscowtimes.ru","DOMAIN-SUFFIX,natribu.org"], "behavior": "classical"},
        "ru-inline": {"type": "inline", "payload": ["DOMAIN-SUFFIX,2ip.ru","DOMAIN-SUFFIX,yastatic.net","DOMAIN-SUFFIX,yandex.net","DOMAIN-SUFFIX,yandex.kz","DOMAIN-SUFFIX,yandex.com","DOMAIN-SUFFIX,vk.com","DOMAIN-SUFFIX,ru","DOMAIN-SUFFIX,su","DOMAIN-SUFFIX,by","DOMAIN-KEYWORD,avito","DOMAIN-KEYWORD,ozon","DOMAIN-KEYWORD,wildberries"], "behavior": "classical"},
    }

def default_proxy_groups() -> List[dict]:
    return [
        {"name": "🚫 Недоступные сайты", "type": "select", "proxies": ["⚡ Минимальная задержка", "🇷🇺 Без VPN"]},
        {"name": "▶️ YouTube", "type": "select", "proxies": ["🚫 Недоступные сайты", "⚡ Минимальная задержка", "🇷🇺 Без VPN"]},
        {"name": "💬 Discord", "type": "select", "proxies": ["🚫 Недоступные сайты", "⚡ Минимальная задержка", "🇷🇺 Без VPN"]},
        {"name": "➤ Telegram", "type": "select", "proxies": ["🚫 Недоступные сайты", "⚡ Минимальная задержка", "🇷🇺 Без VPN"]},
        {"name": "⚪🔵🔴 RU сайты", "type": "select", "proxies": ["🇷🇺 Без VPN"]},
        {"name": "🌍 Остальные сайты", "type": "select", "proxies": ["🚫 Недоступные сайты", "⚡ Минимальная задержка", "🇷🇺 Без VPN"]},
        {
            "name": "⚡ Минимальная задержка",
            "type": "url-test",
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "lazy": True,
            "proxies": []
        },
    ]

def default_rules() -> List[str]:
    return [
        "RULE-SET,geosite-private,DIRECT",
        "RULE-SET,ai,🚫 Недоступные сайты",
        "RULE-SET,google-deepmind,🚫 Недоступные сайты",
        "RULE-SET,speedtest-net,🚫 Недоступные сайты",
        "RULE-SET,youtube,▶️ YouTube",
        "RULE-SET,telegram-ips,➤ Telegram",
        "RULE-SET,telegram-domains,➤ Telegram",
        "RULE-SET,discord_domains,💬 Discord",
        "RULE-SET,ru-inside,🚫 Недоступные сайты",
        "RULE-SET,refilter_domains,🚫 Недоступные сайты",
        "RULE-SET,ru-inline-banned,🚫 Недоступные сайты",
        "RULE-SET,inline-blocked-ips,🚫 Недоступные сайты",
        "RULE-SET,category-porn,🚫 Недоступные сайты",
        "RULE-SET,ru-inline,⚪🔵🔴 RU сайты",
        "RULE-SET,geosite-ru,⚪🔵🔴 RU сайты",
        "RULE-SET,geoip-for-ru,⚪🔵🔴 RU сайты,no-resolve",
        "MATCH,🌍 Остальные сайты",
    ]

def default_mihomo_config() -> dict:
    return {
        "mixed-port": 7890,
        "allow-lan": True,
        "bind-address": "*",
        "tcp-concurrent": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "profile": {"store-selected": True},
        "proxies": [],
        "proxy-groups": default_proxy_groups(),
        "rule-providers": default_rule_providers(),
        "rules": default_rules(),
    }

def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f: 
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_config(cfg: dict) -> None:
    with open(CONFIG_FILE, "w", encoding="utf-8") as f: 
        json.dump(cfg, f, indent=2, ensure_ascii=False)

def decompress(data: bytes) -> bytes:
    if data[:2] == b"\x1f\x8b":
        try: return gzip.decompress(data)
        except: pass
    if data[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
        try: return zlib.decompress(data)
        except: pass
    return data

def fetch_raw(url: str, user_agent: str, headers: dict) -> bytes:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url)
    req.headers["User-Agent"] = user_agent
    req.headers["Accept"] = "*/*"
    for k, v in headers.items():
        req.headers[k] = str(v)

    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        return decompress(resp.read())

def parse_mihomo_yaml(text: str) -> Optional[dict]:
    if not yaml: return None
    try: cfg = yaml.safe_load(text)
    except: return None
    if isinstance(cfg, dict):
        if isinstance(cfg.get("proxies"), list): return cfg
        if isinstance(cfg.get("Proxy"), list): 
            cfg["proxies"] = cfg.pop("Proxy")
            return cfg
    return None

def decode_uri_lines(text: str) -> List[str]:
    return [l.strip() for l in text.splitlines() if l.strip() and any(l.strip().startswith(p) for p in PROTO_PREFIXES)]

def maybe_decode_base64(text: str) -> str:
    try: 
        t = re.sub(r'\s+', '', text.strip()).replace("-", "+").replace("_", "/")
        return base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8", errors="replace")
    except: 
        return ""

def parse_vless(url: str) -> Optional[dict]:
    try:
        p = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(p.query).items()}
        port = int(p.port) if p.port else 443
        net = params.get("type", "tcp")
        sec = params.get("security", "none")
        node = {
            "name": unquote(p.fragment or "vless"),
            "type": "vless",
            "server": p.hostname,
            "port": port,
            "uuid": p.username,
            "network": net,
            "tls": sec in ("tls", "reality"),
            "udp": True
        }
        if sec == "reality":
            node["reality-opts"] = {"public-key": params.get("pbk", ""), "short-id": params.get("sid", "")}
            node["client-fingerprint"] = params.get("fp", "chrome")
            node["servername"] = params.get("sni", p.hostname)
        return node
    except: return None

def parse_vmess(url: str) -> Optional[dict]:
    try:
        t = url[8:].replace("-", "+").replace("_", "/")
        d = json.loads(base64.b64decode(t + "=" * (-len(t) % 4)).decode())
        return {"name": d.get("ps", "vmess"), "type": "vmess", "server": d["add"], "port": int(d.get("port", 443)), "uuid": d["id"], "alterId": int(d.get("aid", 0)), "cipher": "auto", "network": d.get("net", "tcp"), "tls": d.get("tls") == "tls", "udp": True}
    except: return None

def url_to_mihomo(url: str) -> Optional[dict]:
    if url.startswith("vless://"): return parse_vless(url)
    if url.startswith("vmess://"): return parse_vmess(url)
    return None

def build_mihomo_config_from_sources(sources: List[dict]) -> str:
    base_cfg = default_mihomo_config()
    incoming_proxies = []

    for src in sources:
        if src["kind"] == "yaml":
            incoming_proxies.extend([p for p in src["cfg"].get("proxies", []) if isinstance(p, dict)])
        elif src.get("uris"):
            for uri in src["uris"]:
                p = url_to_mihomo(uri)
                if p: incoming_proxies.append(p)

    merged = dedupe_and_merge_proxies(base_cfg.get("proxies", []), incoming_proxies)
    
    proxy_names = [p.get("name") for p in merged if isinstance(p, dict) and p.get("name")]
    clean_remotes = [n for n in proxy_names if n not in {"🇷🇺 Без VPN", "DIRECT"}]

    for g in base_cfg.get("proxy-groups", []):
        if g["name"] == "⚡ Минимальная задержка":
            g["proxies"] = list(clean_remotes)
        elif isinstance(g.get("proxies"), list):
            for cr in clean_remotes:
                if cr not in g["proxies"]: g["proxies"].append(cr)

    if not any(p.get("name") == "🇷🇺 Без VPN" for p in merged if isinstance(p, dict)):
        merged.insert(0, {"name": "🇷🇺 Без VPN", "type": "direct", "udp": True})

    base_cfg["proxies"] = merged
    return yaml.dump(base_cfg, allow_unicode=True, sort_keys=False) if yaml else json.dumps(base_cfg)

def dedupe_and_merge_proxies(existing: List[dict], incoming: List[dict]) -> List[dict]:
    res = copy.deepcopy(existing)
    names = {p["name"] for p in res if "name" in p}
    for p in incoming:
        if not isinstance(p, dict): continue
        p = copy.deepcopy(p)
        base = p.get("name", "proxy")
        final = base; i = 2
        while final in names:
            final = f"{base} #{i}"
            i += 1
        p["name"] = final
        names.add(final)
        res.append(p)
    return res

def collect_entry_sources(entry: dict, cfg: dict) -> List[dict]:
    if entry.get("type") == "merge":
        res = []
        for s in entry.get("sources", []):
            if s in cfg: res.extend(collect_entry_sources(cfg[s], cfg))
        return res
    try:
        url = entry.get("url", "")
        if url.startswith("data:text/yaml;base64,"):
            text = base64.b64decode(url.split(",", 1)[1]).decode("utf-8")
        else:
            text = fetch_raw(url, entry.get("user_agent", "v2rayNG/1.8.9"), entry.get("headers", {})).decode("utf-8", errors="replace")
    except Exception as e:
        return []

    y = parse_mihomo_yaml(text)
    if y: return [{"kind": "yaml", "cfg": y}]
    l = decode_uri_lines(text)
    if l: return [{"kind": "uris", "uris": l}]
    dec = maybe_decode_base64(text)
    if dec:
        l_dec = decode_uri_lines(dec)
        if l_dec: return [{"kind": "uris", "uris": l_dec}]
    return []

# ---------------------------------------------------------------------------
# ПОЛНОФУНКЦИОНАЛЬНЫЙ WEB ИНТЕРФЕЙС
# ---------------------------------------------------------------------------
HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mihomo Hub</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 15px; }
        .container { max-width: 650px; margin: 0 auto; }
        h1 { color: #38bdf8; font-size: 1.5rem; border-bottom: 2px solid #1e293b; padding-bottom: 10px; margin-top: 5px; }
        .card { background: #1e293b; border-radius: 12px; padding: 16px; margin-bottom: 16px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
        .card h3 { margin-top: 0; color: #cbd5e1; font-size: 1.1rem; }
        .btn { background: #0284c7; color: #fff; border: none; padding: 12px; border-radius: 8px; cursor: pointer; font-weight: bold; width: 100%; margin-top: 8px; font-size: 0.95rem; }
        .btn-green { background: #16a34a; }
        .btn-danger { background: #dc2626; padding: 6px 12px; width: auto; font-size: 0.8rem; }
        input, select { width: 100%; background: #0f172a; border: 1px solid #334155; color: #fff; padding: 10px; border-radius: 8px; box-sizing: border-box; margin-bottom: 10px; font-size: 0.95rem; }
        label { font-size: 0.85rem; color: #94a3b8; display: block; margin-bottom: 4px; }
        .sub-item { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding: 10px 0; }
        .sub-link { color: #38bdf8; font-size: 0.8rem; word-break: break-all; margin-top: 4px; display: block; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ Mihomo Android Hub</h1>

        <div class="card">
            <h3>➕ Добавить подписку</h3>
            <form action="/api/add_sub" method="POST">
                <label>Название:</label>
                <input type="text" name="name" placeholder="Например: Мой VPN" required>
                <label>Ссылка на подписку (URL):</label>
                <input type="url" name="url" placeholder="https://..." required>
                <button type="submit" class="btn">Сохранить подписку</button>
            </form>
            <form action="/api/add_warp" method="POST" style="margin-top: 10px;">
                <button type="submit" class="btn btn-green">☁️ Сгенерировать Cloudflare WARP</button>
            </form>
        </div>

        <div class="card">
            <h3>📋 Ваши подписки для FlClash / Hiddify:</h3>
            <div id="subs-list"></div>
        </div>

        <div class="card">
            <h3>⚙️ Кастомная маршрутизация</h3>
            <form action="/api/add_group" method="POST">
                <input type="text" name="name" placeholder="Название (напр. 🎬 Кино)" required>
                <input type="text" name="domains" placeholder="Домены через запятую (hdrezka.ag...)">
                <button type="submit" class="btn">Добавить категорию</button>
            </form>
        </div>
    </div>

    <script>
        const subs = %SUBS_JSON%;
        const container = document.getElementById('subs-list');
        if (Object.keys(subs).length === 0) {
            container.innerHTML = '<p style="color:#64748b; font-size:0.9rem;">Подписок пока нет</p>';
        } else {
            for (const [id, s] of Object.entries(subs)) {
                const div = document.createElement('div');
                div.className = 'sub-item';
                div.innerHTML = `
                    <div style="flex-grow: 1; padding-right: 10px;">
                        <strong>${s.name}</strong>
                        <a class="sub-link" href="http://127.0.0.1:12096/${id}?format=mihomo">http://127.0.0.1:12096/${id}?format=mihomo</a>
                    </div>
                    <form action="/api/delete_sub" method="POST" style="margin:0;">
                        <input type="hidden" name="id" value="${id}">
                        <button type="submit" class="btn btn-danger">Удалить</button>
                    </form>
                `;
                container.appendChild(div);
            }
        }
    </script>
</body>
</html>
"""

class AndroidProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        parsed = urlparse(self.path)
        uid = parsed.path.strip("/")
        if uid == "" or uid == "gui":
            cfg = load_config()
            html = HTML_TEMPLATE.replace("%SUBS_JSON%", json.dumps(cfg, ensure_ascii=False))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        cfg = load_config()
        if uid not in cfg:
            self.send_response(404); self.end_headers(); return

        entry = cfg[uid]
        sources = collect_entry_sources(entry, cfg)
        out_yaml = build_mihomo_config_from_sources(sources).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Content-Length", str(len(out_yaml)))
        self.end_headers()
        self.wfile.write(out_yaml)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = parse_qs(self.rfile.read(length).decode("utf-8"))
        p = urlparse(self.path).path

        if p == "/api/add_sub":
            name = data.get("name", ["VPN"])[0]
            url = data.get("url", [""])[0]
            if url:
                cfg = load_config()
                uid = str(_uuid.uuid4())[:8]
                cfg[uid] = {"name": name, "type": "single", "url": url, "headers": {"x-hwid": str(_uuid.uuid4())}}
                save_config(cfg)
        elif p == "/api/add_warp":
            cfg = load_config()
            uid = str(_uuid.uuid4())[:8]
            cfg[uid] = {"name": "☁️ Cloudflare WARP", "type": "single", "url": "data:text/yaml;base64,cHJveGllczoKICAtIG5hbWU6IFdBUlAKICAgIHR5cGU6IHdpcmVndWFyZAogICAgc2VydmVyOiBlbmdhZ2UuY2xvdWRmbGFyZWNsaWVudC5jb20KICAgIHBvcnQ6IDI0MDgKICAgIGlwOiAxNzIuMTYuMC4y"}
            save_config(cfg)
        elif p == "/api/delete_sub":
            sid = data.get("id", [""])[0]
            cfg = load_config()
            if sid in cfg: del cfg[sid]; save_config(cfg)

        self.send_response(303)
        self.send_header('Location', '/')
        self.end_headers()

def start_server():
    server = HTTPServer(("0.0.0.0", PORT), AndroidProxyHandler)
    server.serve_forever()

# ---------------------------------------------------------------------------
# ЗАПУСК KIVY ГРАФИЧЕСКОГО ИНТЕРФЕЙСА ДЛЯ ANDROID
# ---------------------------------------------------------------------------
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.core.window import Window

class MihomoHubApp(App):
    def build(self):
        Window.clearcolor = (0.06, 0.09, 0.16, 1)
        layout = BoxLayout(orientation='vertical', padding=25, spacing=15)
        
        lbl_title = Label(text="⚡ Mihomo Android Hub", font_size='22sp', bold=True, size_hint_y=0.25)
        lbl_status = Label(text="Сервер работает:\nhttp://127.0.0.1:12096", font_size='16sp', halign='center', color=(0.2, 0.8, 0.4, 1), size_hint_y=0.35)
        
        btn_open = Button(text="🌐 Открыть панель управления", size_hint_y=0.2, background_color=(0.01, 0.52, 0.78, 1))
        btn_open.bind(on_release=lambda x: webbrowser.open("http://127.0.0.1:12096"))
        
        layout.add_widget(lbl_title)
        layout.add_widget(lbl_status)
        layout.add_widget(btn_open)
        return layout

if __name__ == "__main__":
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    MihomoHubApp().run()