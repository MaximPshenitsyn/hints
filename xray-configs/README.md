# VLESS on Linux

## If you have only vless link convert it to json config:
```bash
python vless2json.py "vless://your_link"
# or explicitly define ports via
# python vless2json.py --http-proxy 1080 --socks5-proxy 1090 "vless://your_link"
```

## Copy config to `usr/local`
```bash
cp config.json /usr/local/etc/xray/config.json
```

## Start xray service
```bash
sudo systemctl start xray
# if already running, instead:
# sudo systemctl restart xray
```

## Validate
```bash
sudo lsof -i -P | grep LISTEN                                   # check xray process listens on 2 tcp ports
curl -x http://127.0.0.1:<HTTP_PORT> http://example.com         # check example.com works with http proxy
curl -x socks5://127.0.0.1:<SOCKS5_PORT> http://example.com     # check example.com works with socks5 proxy
```

