import argparse
import json
import sys
from urllib.parse import urlparse, parse_qs


class DotAccessibleDict(dict):
    def __init__(self, missing=False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key, value in self.items():
            if isinstance(value, dict):
                self[key] = DotAccessibleDict(False, value)
        self.__is_missing = missing

    def __bool__(self):
        return not self.__is_missing

    def __getattr__(self, key):
        if key is None or self.__is_missing:
            return DotAccessibleDict(missing=True)
        try:
            return self[key] or DotAccessibleDict(missing=True)
        except KeyError:
            return DotAccessibleDict(missing=True)

    def get_path(self, path, default=None):
        parts = path.split('.')
        current = self
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current


def build_config(raw_params: dict):
    params = DotAccessibleDict(False, raw_params)
    return {
        "log": {
            "access": "none",
            "error": "",
            "loglevel": "warning",
            "dnsLog": False
        },
        "stats": {},
        "policy": {
            "levels": {
              "0": {
                "statsUserUplink": True,
                "statsUserDownlink": True
              }
            },
            "system": {
              "statsOutboundUplink": True,
              "statsOutboundDownlink": True
            }
        },
        "api": {
            "tag": "api",
            "services": [
              "StatsService"
            ]
        },
        "inbounds": [
            {
              "tag": "socks",
              "port": params.proxies.socks_port or 8107,
              "listen": "127.0.0.1",
              "protocol": "socks",
              "sniffing": {
                "enabled": True,
                "destOverride": [
                  "http",
                  "tls"
                ],
                "routeOnly": True
              },
              "settings": {
                "auth": "noauth",
                "udp": True
              }
            },
            {
              "tag": "http",
              "port": params.proxies.http_port or 8108,
              "listen": "127.0.0.1",
              "protocol": "http",
              "sniffing": {
                "enabled": True,
                "destOverride": [
                  "http",
                  "tls"
                ],
                "routeOnly": True
              },
              "settings": {
                "auth": "noauth",
                "udp": True
              }
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": params.server.host,
                            "port": params.server.port,
                            "users": [
                                {
                                    "id": params.uuid,
                                "encryption": "none",
                                "flow": params.params.flow or "xtls-rprx-vision-udp443"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": params.params.type or "tcp",
                    "security": params.params.security or "reality",
                    "realitySettings": {
                        "fingerprint": params.params.fp,
                        "serverName": params.params.sni,
                        "show": False,
                        "publicKey": params.params.pbk,
                        "shortId": params.params.sid
                    }
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            },
            {
                "protocol": "blackhole",
                "tag": "block"
            }
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [
                        "api"
                    ],
                    "outboundTag": "api"
                },
                {
                    "type": "field",
                    "ip": [
                        "geoip:private"
                    ],
                    "outboundTag": "block"
                },
                {
                    "type": "field",
                    "protocol": [
                        "bittorrent"
                    ],
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "port": "6969,6881-6889",
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "sourcePort": "6881-6889",
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "domain": [
                        "ext:customgeo.dat:coherence-extra-exceptions"
                    ],
                    "outboundTag": "proxy"
                },
                {
                    "type": "field",
                    "domain": [
                        "geosite:cn",
                        "domain:cn",
                        "domain:xn--fiqs8s",
                        "domain:xn--fiqz9s",
                        "domain:xn--55qx5d",
                        "domain:xn--io0a7i",
                        "domain:ru",
                        "domain:xn--p1ai",
                        "domain:by",
                        "domain:xn--90ais",
                        "domain:ir",
                        "ext:customgeo.dat:coherence-extra",
                        "ext:customgeo.dat:coherence-extra-plus"
                    ],
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "ip": [
                        "geoip:cn",
                        "geoip:ru",
                        "geoip:by",
                        "geoip:ir"
                    ],
                    "outboundTag": "direct"
                }
            ]
        }
    }

def parse_args() -> argparse.Namespace:
    epilog = """\
Samples:
  vless2json.py 'vless://<UUID>@example.com:443?security=reality&encryption=none'
  vless2json.py --http-proxy 1080 'vless://<UUID>@example.com:443?...'
  vless2json.py --socks5-proxy 1090 'vless://<UUID>@example.com:443?...'
"""
    parser = argparse.ArgumentParser(
        prog="vless2json.py",
        description="Converts VLESS-link to JSON config",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog
    )
    parser.add_argument(
        "vless_link",
        help="VLESS-link in format of vless://<uuid>@host:port?[query...]"
    )
    parser.add_argument(
        "--http-proxy",
        type=int,
        metavar="PORT",
        help="Local HTTP-proxy port (8108 by default)"
    )
    parser.add_argument(
        "--socks5-proxy",
        type=int,
        metavar="PORT",
        help="Local SOCKS5-proxy port (8107 by default)"
    )
    args = parser.parse_args()

    # Валидация портов, если заданы
    for opt_name in ("http_proxy", "socks5_proxy"):
        port = getattr(args, opt_name)
        if port is not None and not (1 <= port <= 65535):
            parser.error(f"--{opt_name.replace('_','-')} should be in range of 1..65535")

    return args

def parse_vless_link(link: str) -> dict:
    if not link.lower().startswith("vless://"):
        sys.exit("Link should start with vless://")
    parsed = urlparse(link)

    if parsed.scheme.lower() != "vless":
        sys.exit("Schema should be vless://")
    uuid = parsed.username
    if not uuid:
        sys.exit("User id is undefined")
    host = parsed.hostname
    port = parsed.port
    if not host or not port:
        sys.exit("Proxy host or port not defined")
    raw_qs = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: (v[0] if isinstance(v, list) and v else "") for k, v in raw_qs.items()}
    name = parsed.fragment if parsed.fragment else None

    return {
        "type": "vless",
        "uuid": uuid,
        "server": {"host": host, "port": port},
        "params": params,
        "name": name
    }

def build_proxies(http_port: int | None, socks_port: int | None) -> dict:
    proxies: dict[str, str] = {}
    if http_port:
        proxies["http_port"] = f"{http_port}"
    if socks_port:
        proxies["socks_port"] = f"{socks_port}"
    return proxies

def main() -> None:
    args = parse_args()
    vless_info = parse_vless_link(args.vless_link)
    result = {
        **vless_info,
        "proxies": build_proxies(args.http_proxy, args.socks5_proxy) or None
    }
    json.dump(build_config(result), open('config.json', 'w'), ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
