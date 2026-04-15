from flask import Flask, jsonify, render_template_string
import socket
import struct
import threading

app = Flask(__name__)

SCAN_RANGES = [
    [f"192.168.20.{i}" for i in range(1, 50)],  
    ["192.168.216.254"],
]
ALL_IPS = [ip for r in SCAN_RANGES for ip in r]


def encode_oid(oid_str):
    parts = list(map(int, oid_str.split(".")))
    first = parts[0] * 40 + parts[1]
    body = [first]
    for p in parts[2:]:
        if p == 0:
            body.append(0)
        else:
            enc = []
            while p:
                enc.append(p & 0x7f)
                p >>= 7
            enc.reverse()
            for i, b in enumerate(enc):
                body.append(b | (0x80 if i < len(enc)-1 else 0))
    return bytes([0x06, len(body)] + body)

def tlv(tag, value):
    return bytes([tag, len(value)]) + value

def build_snmp_get(oid_str, community="public", request_id=1):
    cb = community.encode()
    oe = encode_oid(oid_str)
    null = bytes([0x05, 0x00])
    vb = tlv(0x30, oe + null)
    vbs = tlv(0x30, vb)
    rid = tlv(0x02, struct.pack(">I", request_id).lstrip(b'\x00') or b'\x00')
    err = bytes([0x02, 0x01, 0x00])
    erri = bytes([0x02, 0x01, 0x00])
    gr = tlv(0xa0, rid + err + erri + vbs)
    v = bytes([0x02, 0x01, 0x00])
    ct = tlv(0x04, cb)
    return tlv(0x30, v + ct + gr)

def build_snmp_getnext(oid_str, community="public", request_id=1):
    cb = community.encode()
    oe = encode_oid(oid_str)
    null = bytes([0x05, 0x00])
    vb = tlv(0x30, oe + null)
    vbs = tlv(0x30, vb)
    rid = tlv(0x02, struct.pack(">I", request_id).lstrip(b'\x00') or b'\x00')
    err = bytes([0x02, 0x01, 0x00])
    erri = bytes([0x02, 0x01, 0x00])
    gr = tlv(0xa1, rid + err + erri + vbs)
    v = bytes([0x02, 0x01, 0x00])
    ct = tlv(0x04, cb)
    return tlv(0x30, v + ct + gr)

def parse_snmp_response(data):
    try:
        oid_positions = []
        i = 0
        while i < len(data):
            if data[i] == 0x06:
                oid_positions.append(i)
            i += 1
        oid_val = ""
        if len(oid_positions) >= 2:
            oid_idx = oid_positions[1]
            oid_len = data[oid_idx + 1]
            oid_bytes = data[oid_idx + 2: oid_idx + 2 + oid_len]
            parts = []
            if oid_bytes:
                first = oid_bytes[0]
                parts.append(str(first // 40))
                parts.append(str(first % 40))
                j = 1
                while j < len(oid_bytes):
                    v = 0
                    while j < len(oid_bytes) and oid_bytes[j] & 0x80:
                        v = (v << 7) | (oid_bytes[j] & 0x7f)
                        j += 1
                    if j < len(oid_bytes):
                        v = (v << 7) | oid_bytes[j]
                        j += 1
                    parts.append(str(v))
            oid_val = '.'.join(parts)
        elif oid_positions:
            oid_idx = oid_positions[0]
            oid_len = data[oid_idx + 1]
            oid_bytes = data[oid_idx + 2: oid_idx + 2 + oid_len]
            parts = []
            if oid_bytes:
                first = oid_bytes[0]
                parts.append(str(first // 40))
                parts.append(str(first % 40))
                j = 1
                while j < len(oid_bytes):
                    v = 0
                    while j < len(oid_bytes) and oid_bytes[j] & 0x80:
                        v = (v << 7) | (oid_bytes[j] & 0x7f)
                        j += 1
                    if j < len(oid_bytes):
                        v = (v << 7) | oid_bytes[j]
                        j += 1
                    parts.append(str(v))
            oid_val = '.'.join(parts)
        val = parse_snmp_value(data)
        return oid_val, val
    except:
        return "", "N/A"

def parse_snmp_value(data):
    try:
        pdu_idx = data.find(b'\xa2')
        if pdu_idx == -1:
            return "N/A"
        i = pdu_idx + 1
        if data[i] & 0x80:
            i += (data[i] & 0x7f) + 1
        else:
            i += 1
        if data[i] == 0x02:
            i += 2 + data[i+1]
        if data[i] == 0x02:
            i += 2 + data[i+1]
        if data[i] == 0x02:
            i += 2 + data[i+1]
        if data[i] != 0x30:
            return "N/A"
        i += 1
        if data[i] & 0x80:
            i += (data[i] & 0x7f) + 1
        else:
            i += 1
        if data[i] != 0x30:
            return "N/A"
        i += 1
        if data[i] & 0x80:
            i += (data[i] & 0x7f) + 1
        else:
            i += 1
        if data[i] != 0x06:
            return "N/A"
        oid_len = data[i+1]
        i += 2 + oid_len
        val_type = data[i]
        val_len  = data[i+1]
        val_data = data[i+2: i+2+val_len]
        if val_type == 0x04:
            return val_data.decode('utf-8', errors='ignore').strip()
        if val_type in (0x02, 0x41, 0x42, 0x43):
            return str(int.from_bytes(val_data, 'big', signed=False))
        if val_type == 0x05:
            return "N/A"
        if val_type == 0x40 and len(val_data) == 4:
            return '.'.join(str(b) for b in val_data)
        if val_type == 0x06:
            parts = []
            if val_data:
                first = val_data[0]
                parts.append(str(first // 40))
                parts.append(str(first % 40))
                j = 1
                while j < len(val_data):
                    v = 0
                    while j < len(val_data) and val_data[j] & 0x80:
                        v = (v << 7) | (val_data[j] & 0x7f)
                        j += 1
                    if j < len(val_data):
                        v = (v << 7) | val_data[j]
                        j += 1
                    parts.append(str(v))
            return '.'.join(parts)
        return "N/A"
    except:
        return "N/A"

def snmp_get(ip, oid, community="public", timeout=2):
    try:
        pkt = build_snmp_get(oid, community)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (ip, 161))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return parse_snmp_value(data)
    except:
        return None

def snmp_getnext(ip, oid, community="public", timeout=2):
    try:
        pkt = build_snmp_getnext(oid, community)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (ip, 161))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return parse_snmp_response(data)
    except:
        return ("", None)

def get_interfaces(ip, community="public"):
    interfaces = []
    STATUS_MAP = {"1": "up", "2": "down", "3": "testing", "4": "unknown", "5": "dormant"}
    base_descr  = "1.3.6.1.2.1.2.2.1.2"
    base_status = "1.3.6.1.2.1.2.2.1.8"
    base_speed  = "1.3.6.1.2.1.2.2.1.5"
    base_type   = "1.3.6.1.2.1.2.2.1.3"
    current = base_descr
    seen = set()
    for _ in range(20):
        oid_resp, val = snmp_getnext(ip, current)
        if not val or not oid_resp or not oid_resp.startswith(base_descr):
            break
        if oid_resp in seen:
            break
        seen.add(oid_resp)
        idx = oid_resp[len(base_descr)+1:]
        if not idx:
            break
        status_oid = f"{base_status}.{idx}"
        speed_oid  = f"{base_speed}.{idx}"
        raw_status = snmp_get(ip, status_oid) or "?"
        raw_speed  = snmp_get(ip, speed_oid) or "0"
        status_str = STATUS_MAP.get(raw_status, raw_status)
        try:
            speed_bps = int(raw_speed)
            if speed_bps >= 1_000_000_000:
                speed_str = f"{speed_bps//1_000_000_000} Gbps"
            elif speed_bps >= 1_000_000:
                speed_str = f"{speed_bps//1_000_000} Mbps"
            elif speed_bps > 0:
                speed_str = f"{speed_bps//1000} Kbps"
            else:
                speed_str = "—"
        except:
            speed_str = "—"
        interfaces.append({"name": val, "status": status_str, "speed": speed_str})
        current = oid_resp
    interfaces = [i for i in interfaces if not i['name'].lower().startswith(('null','loopback','loop'))]
    return interfaces[:12]

def format_uptime(ticks_str):
    try:
        ticks = int(ticks_str)
        total_secs = ticks // 100
        days = total_secs // 86400
        hours = (total_secs % 86400) // 3600
        mins = (total_secs % 3600) // 60
        if days > 0:
            return f"{days}d {hours}h {mins}m"
        return f"{hours}h {mins}m"
    except:
        return ticks_str

def get_device_detail(ip):
    results = {}
    oids = {
        "hostname":    "1.3.6.1.2.1.1.5.0",
        "description": "1.3.6.1.2.1.1.1.0",
        "uptime":      "1.3.6.1.2.1.1.3.0",
        "contact":     "1.3.6.1.2.1.1.4.0",
        "location":    "1.3.6.1.2.1.1.6.0",
        "objectid":    "1.3.6.1.2.1.1.2.0",
        "if_count":    "1.3.6.1.2.1.2.1.0",
    }
    lock = threading.Lock()
    def fetch(key, oid):
        val = snmp_get(ip, oid)
        with lock:
            results[key] = val or "—"
    threads = [threading.Thread(target=fetch, args=(k, v)) for k, v in oids.items()]
    for t in threads: t.start()
    for t in threads: t.join()
    desc = results.get("description", "")
    model = "—"
    os_version = "—"
    if "Cisco" in desc:
        parts = desc.split(",")
        if len(parts) > 0:
            model_part = parts[0].strip()
            model = model_part[:60] if model_part else "Cisco IOS"
        if "Version" in desc:
            try:
                v_start = desc.index("Version") + 8
                v_end = desc.index(",", v_start) if "," in desc[v_start:] else v_start + 20
                os_version = desc[v_start:v_end].strip()
            except:
                os_version = "IOS"
    uptime_raw = results.get("uptime", "—")
    uptime_fmt = format_uptime(uptime_raw) if uptime_raw != "—" else "—"
    interfaces = get_interfaces(ip)
    # FIX: detect router by hostname
    dev_type = "router" if results.get("hostname","").lower() == "router" else "switch"
    return {
        "ip": ip,
        "type": dev_type,
        "status": "online",
        "hostname": results.get("hostname", "—"),
        "model": model,
        "os_version": os_version,
        "full_description": desc[:120] if desc else "—",
        "uptime": uptime_fmt,
        "uptime_raw": uptime_raw,
        "contact": results.get("contact", "—"),
        "location": results.get("location", "—"),
        "object_id": results.get("objectid", "—"),
        "if_count": results.get("if_count", "—"),
        "interfaces": interfaces,
    }

def probe_device(ip):
    hostname = snmp_get(ip, "1.3.6.1.2.1.1.5.0")
    if not hostname:
        return None
    # FIX: detect router by hostname
    dev_type = "router" if hostname.lower() == "router" else "switch"
    return {
        "name": hostname, "ip": ip, "type": dev_type, "status": "online",
        "hostname": hostname,
    }

def get_lldp_neighbors(ip, community="public"):
    neighbors = []
    base = "1.0.8802.1.1.2.1.4.1.1.9"
    current = base
    seen = set()
    for _ in range(20):
        oid_resp, val = snmp_getnext(ip, current)
        if not val or val in ("N/A", "—") or not oid_resp:
            break
        if not oid_resp.startswith(base):
            break
        if oid_resp in seen:
            break
        seen.add(oid_resp)
        if val and val not in ("N/A", "—"):
            neighbors.append(val.strip())
        current = oid_resp
    return neighbors

def discover_topology():
    results = {}
    seen_hostnames = set()
    lock = threading.Lock()
    def probe(ip):
        info = probe_device(ip)
        if info:
            hostname = info["name"]
            with lock:
                if hostname not in seen_hostnames:
                    seen_hostnames.add(hostname)
                    results[ip] = info
    threads = [threading.Thread(target=probe, args=(ip,)) for ip in ALL_IPS]
    for t in threads: t.start()
    for t in threads: t.join()
    nodes = list(results.values())
    node_names = {n["name"] for n in nodes}
    links_set = set()
    def fetch_neighbors(node):
        neighbors = get_lldp_neighbors(node["ip"])
        for nb in neighbors:
            if nb in node_names and nb != node["name"]:
                pair = tuple(sorted([node["name"], nb]))
                with lock:
                    links_set.add(pair)
    nb_threads = [threading.Thread(target=fetch_neighbors, args=(n,)) for n in nodes]
    for t in nb_threads: t.start()
    for t in nb_threads: t.join()
    if links_set:
        links = [{"source": a, "target": b} for a, b in links_set]
    else:
        sorted_nodes = sorted(nodes, key=lambda n: n["name"])
        links = []
        for i in range(len(sorted_nodes)-1):
            links.append({"source": sorted_nodes[i]["name"], "target": sorted_nodes[i+1]["name"]})
    return {"nodes": nodes, "links": links}

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/topology')
def topology():
    return jsonify(discover_topology())

@app.route('/api/device/<path:ip>')
def device_detail(ip):
    return jsonify(get_device_detail(ip))


HTML = r'''<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sistema de Topología de Red</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='45' fill='%230ea5e9'/><circle cx='50' cy='50' r='18' fill='white'/><circle cx='50' cy='10' r='6' fill='white'/><circle cx='50' cy='90' r='6' fill='white'/><circle cx='10' cy='50' r='6' fill='white'/><circle cx='90' cy='50' r='6' fill='white'/></svg>">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
:root{--bg:#080e18;--panel:#0c1422;--panel2:#111d30;--border:#1a2740;--border2:#1e3050;--blue:#3b82f6;--blue2:#2563eb;--cyan:#06b6d4;--green:#22c55e;--green2:#16a34a;--red:#ef4444;--amber:#f59e0b;--text:#e2e8f0;--text2:#94a3b8;--text3:#475569;--shadow:0 4px 20px rgba(0,0,0,.4)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'DM Sans',system-ui,sans-serif;background:var(--bg);color:var(--text);height:100vh;display:flex;flex-direction:column;overflow:hidden}
header{height:58px;padding:0 22px;background:linear-gradient(90deg,#060c18,#0a1428 50%,#060c18);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;position:relative;z-index:10;box-shadow:0 2px 20px rgba(0,0,0,.5)}
header::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(59,130,246,.5),rgba(6,182,212,.4),transparent)}
.hlogo{display:flex;align-items:center;gap:11px}
.hmark{width:34px;height:34px;background:linear-gradient(135deg,var(--blue2),var(--cyan));border-radius:9px;display:flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 2px 14px rgba(37,99,235,.4)}
.hmark svg{width:19px;height:19px}
.htitle{font-size:13px;font-weight:700;color:#f1f5f9;letter-spacing:.01em}
.hsub{font-size:9px;color:var(--text3);letter-spacing:.1em;text-transform:uppercase;margin-top:1px;font-weight:500}
.hright{display:flex;align-items:center;gap:9px}
.hlive{display:none;align-items:center;gap:6px;font-size:11px;font-weight:600;color:#4ade80;padding:4px 12px;border-radius:20px;background:rgba(74,222,128,.07);border:1px solid rgba(74,222,128,.2)}
.hlive.on{display:flex}
.hpulse{width:6px;height:6px;background:#4ade80;border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(74,222,128,.4)}70%{box-shadow:0 0 0 5px rgba(74,222,128,0)}}
.hscan{display:flex;align-items:center;gap:7px;padding:8px 17px;border-radius:8px;border:none;background:linear-gradient(135deg,var(--blue2),#0891b2);font-size:12px;font-weight:700;cursor:pointer;color:#fff;font-family:'DM Sans',sans-serif;letter-spacing:.03em;transition:all .2s;box-shadow:0 2px 14px rgba(37,99,235,.35)}
.hscan:hover{transform:translateY(-2px);box-shadow:0 6px 22px rgba(37,99,235,.5)}
.hscan:disabled{opacity:.38;cursor:not-allowed;transform:none}
.hscan svg{width:13px;height:13px;stroke:currentColor;stroke-width:2.5;fill:none}
.main{display:flex;flex:1;overflow:hidden}
.sidebar{width:258px;background:var(--panel);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;flex-shrink:0;transition:width .22s}
.sidebar.off{width:0;border:none}
.sbh{padding:12px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;min-width:258px;flex-shrink:0}
.sblbl{font-size:9px;font-weight:700;color:var(--text3);letter-spacing:.12em;text-transform:uppercase}
.sbct{font-size:10px;font-weight:700;color:var(--blue);background:rgba(59,130,246,.1);padding:2px 9px;border-radius:10px;border:1px solid rgba(59,130,246,.2)}
.sblist{overflow-y:auto;flex:1;padding:8px}
.sblist::-webkit-scrollbar{width:3px}
.sblist::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
.sbempty{color:var(--text3);font-size:12px;text-align:center;padding:28px 0;font-weight:500}
.dcard{background:var(--panel2);border:1.5px solid var(--border);border-radius:11px;padding:11px 13px;margin-bottom:7px;cursor:pointer;transition:all .15s;position:relative;overflow:hidden}
.dcard::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:transparent;border-radius:3px 0 0 3px;transition:background .15s}
.dcard:hover{border-color:var(--blue);background:#0f1e35;box-shadow:0 4px 18px rgba(59,130,246,.15)}
.dcard:hover::before,.dcard.sel::before{background:linear-gradient(to bottom,var(--blue),var(--cyan))}
.dcard.sel{border-color:var(--blue2);background:#0f1e35}
.dcrow{display:flex;align-items:center;gap:9px;margin-bottom:8px}
.dcico{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:14px}
.dcico.r{background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.25)}
.dcico.s{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.2)}
.dcname{font-size:12px;font-weight:700;color:#e2e8f0;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dcip{font-size:10px;color:var(--text3);font-family:'DM Mono',monospace;margin-top:1px}
.dcled{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 6px rgba(34,197,94,.45);flex-shrink:0;margin-left:auto}
.dcmeta{display:grid;grid-template-columns:1fr 1fr;gap:4px}
.dmlbl{font-size:8px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.07em}
.dmval{font-size:10px;color:var(--text2);font-weight:600;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cvwrap{flex:1;display:flex;flex-direction:column;overflow:hidden}
.cvbar{background:var(--panel);border-bottom:1px solid var(--border);padding:7px 14px;display:flex;align-items:center;gap:8px;flex-shrink:0}
.tbtn{width:26px;height:26px;border-radius:7px;border:1px solid var(--border2);background:var(--panel2);cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--text3);transition:all .14s;flex-shrink:0}
.tbtn:hover{background:#0f1e35;border-color:var(--blue);color:var(--blue)}
.tbtn svg{width:12px;height:12px;stroke:currentColor;stroke-width:2.5;fill:none}
.bsep{width:1px;height:16px;background:var(--border);margin:0 2px}
.bstats{display:none;align-items:center;gap:14px}
.bstats.on{display:flex}
.bs{font-size:11px;color:var(--text3);font-weight:500}
.bs b{color:var(--text);font-weight:700}
.bs.g b{color:var(--green)}
.bs.r b{color:var(--red)}
.blbl{font-size:9px;color:var(--text3);font-weight:700;margin-left:auto;letter-spacing:.1em;text-transform:uppercase}
#mapwrap{flex:1;position:relative;overflow:hidden;background:var(--bg);background-image:radial-gradient(circle,#1a2740 1px,transparent 1px);background-size:24px 24px}
svg#topo{width:100%;height:100%}
.welcome{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(8,14,24,.88);z-index:5;backdrop-filter:blur(8px)}
.wcard{background:var(--panel);border:1px solid var(--border2);border-radius:20px;padding:50px 54px;text-align:center;max-width:460px;box-shadow:0 20px 60px rgba(0,0,0,.6);animation:wfade .4s ease}
@keyframes wfade{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
.wring{width:78px;height:78px;margin:0 auto 22px;position:relative}
.wring svg{width:78px;height:78px;animation:wspin 14s linear infinite}
@keyframes wspin{to{transform:rotate(360deg)}}
.wdot{position:absolute;inset:0;display:flex;align-items:center;justify-content:center}
.wdot-inner{width:18px;height:18px;background:linear-gradient(135deg,var(--blue),var(--cyan));border-radius:50%;box-shadow:0 0 18px rgba(59,130,246,.5)}
.wcard h2{font-size:19px;font-weight:800;color:#f1f5f9;margin-bottom:10px;line-height:1.35}
.wcard p{font-size:13px;color:var(--text2);margin-bottom:28px;line-height:1.75}
.wbtn{display:inline-flex;align-items:center;gap:8px;padding:12px 32px;border-radius:10px;border:none;background:linear-gradient(135deg,var(--blue2),#0891b2);font-size:13px;font-weight:700;cursor:pointer;color:#fff;font-family:'DM Sans',sans-serif;transition:all .2s;box-shadow:0 4px 18px rgba(37,99,235,.35)}
.wbtn:hover{transform:translateY(-2px);box-shadow:0 8px 28px rgba(37,99,235,.5)}
.wbtn svg{width:14px;height:14px;stroke:currentColor;stroke-width:2.5;fill:none}
.wtags{display:flex;gap:8px;justify-content:center;margin-top:20px;flex-wrap:wrap}
.wtag{font-size:10px;color:var(--text3);font-weight:600;background:rgba(255,255,255,.04);border:1px solid var(--border2);padding:4px 12px;border-radius:20px}
.loading{position:absolute;inset:0;display:none;flex-direction:column;align-items:center;justify-content:center;gap:16px;background:rgba(8,14,24,.9);z-index:5;backdrop-filter:blur(8px)}
.loading.on{display:flex}
.ldring{width:46px;height:46px;border:3px solid var(--border2);border-top-color:var(--blue);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.ldtitle{font-size:14px;font-weight:700;color:var(--text)}
.ldsub{font-size:11px;color:var(--text3)}
.ldpts{display:flex;gap:5px}
.ldpt{width:5px;height:5px;background:var(--blue);border-radius:50%;animation:ldp .8s infinite}
.ldpt:nth-child(2){animation-delay:.15s}
.ldpt:nth-child(3){animation-delay:.3s}
@keyframes ldp{0%,80%,100%{transform:scale(.5);opacity:.3}40%{transform:scale(1);opacity:1}}
.detail{width:310px;background:var(--panel);border-left:1px solid var(--border);display:none;flex-direction:column;overflow:hidden;flex-shrink:0}
.detail.on{display:flex}
.detail.shut{width:0;border:none;display:none!important}
.dhead{padding:14px 16px;border-bottom:1px solid var(--border);flex-shrink:0}
.dheadrow{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.dheadico{width:42px;height:42px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:20px}
.dheadico.r{background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.25)}
.dheadico.s{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.2)}
.dhn{font-size:15px;font-weight:800;color:#f1f5f9}
.dhip{font-size:10px;color:var(--text3);font-family:'DM Mono',monospace;margin-top:3px}
.dhbadge{display:inline-flex;align-items:center;gap:5px;font-size:10px;font-weight:700;color:var(--green);background:rgba(34,197,94,.07);border:1px solid rgba(34,197,94,.2);padding:3px 10px;border-radius:20px}
.dhbadge::before{content:'';width:5px;height:5px;background:var(--green);border-radius:50%;box-shadow:0 0 5px rgba(34,197,94,.5)}
.dbody{overflow-y:auto;flex:1;padding:14px 16px}
.dbody::-webkit-scrollbar{width:3px}
.dbody::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
.snmpl{display:flex;align-items:center;gap:9px;padding:22px 0;color:var(--text3);font-size:12px;font-weight:600}
.snmlring{width:16px;height:16px;border:2px solid var(--border2);border-top-color:var(--blue);border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0}
.mbanner{background:linear-gradient(135deg,#060c18,#0f1e35 60%,#0a1e3a);border:1px solid var(--border2);border-radius:11px;padding:13px 15px;margin-bottom:14px;position:relative;overflow:hidden}
.mbanner::after{content:'';position:absolute;top:-15px;right:-15px;width:70px;height:70px;border-radius:50%;background:rgba(59,130,246,.06)}
.mtitle{font-size:13px;font-weight:800;color:#f1f5f9;margin-bottom:3px}
.msub{font-size:10px;color:var(--text3);font-family:'DM Mono',monospace}
.isec{margin-bottom:16px}
.isech{font-size:10px;font-weight:800;color:#cbd5f5;letter-spacing:.12em;text-transform:uppercase;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px}
.isech::before{content:'';width:2px;height:11px;background:linear-gradient(to bottom,var(--blue),var(--cyan));border-radius:2px;flex-shrink:0}
.irow{display:flex;justify-content:space-between;align-items:flex-start;padding:4px 0;font-size:11px}
.irow+.irow{border-top:1px solid #0a1020}
.ik{color:#94a3b8;font-weight:600;flex-shrink:0;margin-right:8px}
.iv{color:#f1f5f9;font-weight:700;font-size:12px;text-align:right;max-width:175px;word-break:break-all}
.iv.mo{font-family:'DM Mono',monospace;color:#60a5fa;font-size:11px;font-weight:600}
.iftable{width:100%;border-collapse:collapse;font-size:11px;margin-top:6px}
.iftable th{color:var(--text3);font-weight:700;text-align:left;padding:4px 7px;border-bottom:1px solid var(--border);font-size:9px;letter-spacing:.08em;text-transform:uppercase}
.iftable td{padding:4px 7px;border-bottom:1px solid #0a1020;vertical-align:middle}
.iftable tr:last-child td{border-bottom:none}
.iftable tr:hover td{background:rgba(255,255,255,.02)}
.ifname{font-family:'DM Mono',monospace;color:var(--text2);font-size:10px}
.sup{color:var(--green);font-weight:800}
.sdown{color:var(--red);font-weight:800}
.sdot{width:6px;height:6px;border-radius:50%;display:inline-block;margin-right:4px;vertical-align:middle}
.dup{background:var(--green);box-shadow:0 0 4px rgba(34,197,94,.4)}
.ddn{background:var(--red);box-shadow:0 0 4px rgba(239,68,68,.4)}
.spdtag{font-size:9px;font-weight:700;color:var(--blue);background:rgba(59,130,246,.1);padding:2px 6px;border-radius:4px;border:1px solid rgba(59,130,246,.2)}
.osbox{background:#060c18;border:1px solid #1e3050;border-radius:8px;padding:12px 14px;font-size:11px;color:#cbd5f5;font-family:'DM Mono',monospace;line-height:1.7;word-break:break-all;box-shadow:inset 0 0 12px rgba(59,130,246,.08)}
#toast{position:fixed;bottom:20px;right:20px;background:var(--panel2);color:var(--text);padding:10px 16px;border-radius:9px;font-size:12px;font-weight:600;z-index:999;opacity:0;transition:opacity .25s;box-shadow:0 8px 24px rgba(0,0,0,.4);pointer-events:none;border:1px solid var(--border2);display:flex;align-items:center;gap:7px;font-family:'DM Sans',sans-serif}
#toast.on{opacity:1}
#toast::before{content:'';width:5px;height:5px;background:var(--cyan);border-radius:50%;flex-shrink:0}
</style>
</head>
<body>
<div id="toast"><span></span></div>
<header>
  <div class="hlogo">
    <div class="hmark">
      <svg viewBox="0 0 19 19" fill="none">
        <circle cx="9.5" cy="9.5" r="8" stroke="rgba(255,255,255,.45)" stroke-width="1.2"/>
        <circle cx="9.5" cy="9.5" r="4.5" stroke="rgba(255,255,255,.65)" stroke-width="1"/>
        <circle cx="9.5" cy="9.5" r="1.9" fill="white"/>
        <circle cx="9.5" cy="2" r="1.6" fill="white" opacity=".7"/>
        <circle cx="9.5" cy="17" r="1.6" fill="white" opacity=".7"/>
        <circle cx="2" cy="9.5" r="1.6" fill="white" opacity=".7"/>
        <circle cx="17" cy="9.5" r="1.6" fill="white" opacity=".7"/>
      </svg>
    </div>
    <div>
      <div class="htitle">Sistema de Descubrimiento y Gestión de Topología de Red</div>
      <div class="hsub">SNMP · LLDP · Tiempo real</div>
    </div>
  </div>
  <div class="hright">
    <div class="hlive" id="hlive"><div class="hpulse"></div>Sistema activo</div>
    <button class="hscan" id="scanbtn" onclick="scan()">
      <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
      Escanear Red
    </button>
  </div>
</header>
<div class="main">
  <div class="sidebar" id="sidebar">
    <div class="sbh"><span class="sblbl">Dispositivos</span><span class="sbct" id="sbct">0</span></div>
    <div class="sblist" id="sblist"><div class="sbempty">Escanea la red para descubrir dispositivos</div></div>
  </div>
  <div class="cvwrap">
    <div class="cvbar">
      <div class="tbtn" onclick="toggleSB()"><svg viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg></div>
      <div class="bsep"></div>
      <div class="bstats" id="bstats">
        <span class="bs">Nodos: <b id="bsn">0</b></span>
        <span class="bs g">En línea: <b id="bson">0</b></span>
        <span class="bs r">Fuera: <b id="bsoff">0</b></span>
        <span class="bs">Links: <b id="bsl">0</b></span>
      </div>
      <span class="blbl">Mapa de red</span>
      <div class="bsep"></div>
      <div class="tbtn" onclick="toggleDT()"><svg viewBox="0 0 24 24"><path d="M9 18l6-6-6-6"/></svg></div>
    </div>
    <div id="mapwrap">
      <div class="welcome" id="welcome">
        <div class="wcard">
          <div class="wring">
            <svg viewBox="0 0 78 78" fill="none">
              <circle cx="39" cy="39" r="35" stroke="#1a2740" stroke-width="1.5"/>
              <circle cx="39" cy="39" r="22" stroke="#1e3050" stroke-width="1.5" stroke-dasharray="4 3"/>
              <circle cx="39" cy="5" r="4" fill="#3b82f6"/><circle cx="73" cy="39" r="4" fill="#06b6d4"/>
              <circle cx="39" cy="73" r="4" fill="#3b82f6"/><circle cx="5" cy="39" r="4" fill="#06b6d4"/>
              <circle cx="62" cy="12" r="3" fill="#22c55e"/><circle cx="66" cy="62" r="3" fill="#22c55e"/>
              <circle cx="12" cy="62" r="3" fill="#f59e0b"/><circle cx="12" cy="16" r="3" fill="#f59e0b"/>
            </svg>
            <div class="wdot"><div class="wdot-inner"></div></div>
          </div>
          <h2>Sistema de Descubrimiento y<br>Gestión de Topología de Red</h2>
          <p>Descubre automáticamente todos los dispositivos de red. Haz clic en cualquier nodo para ver sus metadatos técnicos en tiempo real via SNMP.</p>
          <button class="wbtn" onclick="scan()">
            <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            Iniciar Descubrimiento
          </button>
          <div class="wtags">
            <span class="wtag">Autodescubrimiento SNMP</span>
            <span class="wtag">Topología LLDP</span>
            <span class="wtag">Actualización automática</span>
          </div>
        </div>
      </div>
      <div class="loading" id="loading">
        <div class="ldring"></div>
        <div class="ldtitle">Descubriendo dispositivos...</div>
        <div class="ldsub">Consultando via SNMP · 192.168.20.2–50 + Router</div>
        <div class="ldpts"><div class="ldpt"></div><div class="ldpt"></div><div class="ldpt"></div></div>
      </div>
      <svg id="topo"></svg>
    </div>
  </div>
  <div class="detail" id="detail">
    <div class="dhead">
      <div class="dheadrow">
        <div class="dheadico" id="dico"></div>
        <div><div class="dhn" id="dhn">—</div><div class="dhip" id="dhip">—</div></div>
      </div>
      <div class="dhbadge">En línea</div>
    </div>
    <div class="dbody" id="dbody">
      <div style="color:var(--text3);font-size:12px;padding:24px 0;text-align:center;font-weight:600;line-height:1.7">Haz clic en un nodo<br>para ver sus metadatos SNMP</div>
    </div>
  </div>
</div>
<script>
let gdata=null,sim=null,sbOn=true,dtOn=false,rt=null;
function drawR(g,w,h){
  const hw=w/2,hh=h/2;
  g.append('rect').attr('x',-hw).attr('y',-hh).attr('width',w).attr('height',h).attr('rx',11).attr('fill','#0d1e38').attr('stroke','#2563eb').attr('stroke-width',2);
  g.append('rect').attr('x',-hw).attr('y',-hh).attr('width',w).attr('height',hh*0.55).attr('rx',11).attr('fill','rgba(37,99,235,.07)');
  g.append('circle').attr('cx',-hw*0.44).attr('cy',0).attr('r',hh*0.52).attr('fill','none').attr('stroke','#2563eb').attr('stroke-width',1.5);
  g.append('circle').attr('cx',-hw*0.44).attr('cy',0).attr('r',hh*0.19).attr('fill','#3b82f6');
  [-hw*0.06,hw*0.19,hw*0.44,hw*0.69].forEach(x=>{[-hh*0.25,0,hh*0.25].forEach(y=>{g.append('line').attr('x1',x).attr('y1',y).attr('x2',x+hw*0.19).attr('y2',y).attr('stroke','#1d4ed8').attr('stroke-width',1.1).attr('stroke-dasharray','3.5 2');});});
  g.append('circle').attr('cx',hw*0.74).attr('cy',-hh*0.52).attr('r',6.5).attr('fill','#2563eb').attr('stroke','rgba(59,130,246,.3)').attr('stroke-width',2);
  g.append('line').attr('x1',hw*0.74).attr('y1',-hh*0.52-6.5).attr('x2',hw*0.74+9).attr('y2',-hh*0.52-16).attr('stroke','#3b82f6').attr('stroke-width',1.5);
  g.append('line').attr('x1',hw*0.74+6).attr('y1',-hh*0.52).attr('x2',hw*0.74+17).attr('y2',-hh*0.52).attr('stroke','#3b82f6').attr('stroke-width',1.5);
}
function drawS(g,w,h){
  const hw=w/2,hh=h/2;
  g.append('rect').attr('x',-hw).attr('y',-hh).attr('width',w).attr('height',h).attr('rx',9).attr('fill','#0a1e14').attr('stroke','#16a34a').attr('stroke-width',2);
  g.append('rect').attr('x',-hw).attr('y',-hh).attr('width',w).attr('height',hh*0.6).attr('rx',9).attr('fill','rgba(22,163,74,.07)');
  const ps=[-hw+10,-hw+21,-hw+32,-hw+43,-hw+54,-hw+65];
  ps.forEach(px=>{if(px<hw-8){g.append('rect').attr('x',px).attr('y',-3.5).attr('width',8.5).attr('height',7).attr('rx',1.8).attr('fill','#060f08').attr('stroke','rgba(34,197,94,.3)').attr('stroke-width',1);}});
  const lc=['#22c55e','#22c55e','#f59e0b','#22c55e'];
  [-hw+6,-hw+14,-hw+22,-hw+30].forEach((lx,i)=>{g.append('circle').attr('cx',lx).attr('cy',-hh+7.5).attr('r',2.8).attr('fill',lc[i]).attr('opacity',.85);});
  g.append('circle').attr('cx',hw-8).attr('cy',-hh+7.5).attr('r',3).attr('fill','#22c55e');
}
async function scan(){
  const btn=document.getElementById('scanbtn');
  btn.disabled=true;
  btn.innerHTML='<svg viewBox="0 0 24 24" style="width:13px;height:13px;stroke:currentColor;stroke-width:2.5;fill:none;animation:spin .7s linear infinite"><path d="M21 12a9 9 0 11-9-9c2.4 0 4.6.9 6.3 2.4"/></svg> Escaneando...';
  document.getElementById('welcome').style.display='none';
  document.getElementById('loading').classList.add('on');
  document.getElementById('topo').innerHTML='';
  try{
    const r=await fetch('/api/topology');
    gdata=await r.json();
    document.getElementById('loading').classList.remove('on');
    draw(gdata);buildSB(gdata);updateBar(gdata);
    document.getElementById('hlive').classList.add('on');
    startRT();
  }catch(e){
    document.getElementById('loading').classList.remove('on');
    document.getElementById('welcome').style.display='flex';
  }
  btn.disabled=false;
  btn.innerHTML='<svg viewBox="0 0 24 24" style="width:13px;height:13px;stroke:currentColor;stroke-width:2.5;fill:none"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg> Escanear Red';
}
function startRT(){
  if(rt)clearInterval(rt);
  rt=setInterval(async()=>{
    if(!gdata)return;
    try{
      const r=await fetch('/api/topology');
      const nd=await r.json();
      const oN=new Set(gdata.nodes.map(n=>n.name));
      const nN=new Set(nd.nodes.map(n=>n.name));
      const ch=nd.nodes.length!==gdata.nodes.length||[...nN].some(n=>!oN.has(n))||[...oN].some(n=>!nN.has(n));
      gdata=nd;buildSB(nd);updateBar(nd);
      if(ch){draw(nd);toast('Topología actualizada');}
    }catch(e){}
  },30000);
}
function toast(m){const t=document.getElementById('toast');t.querySelector('span').textContent=m;t.classList.add('on');setTimeout(()=>t.classList.remove('on'),3000);}
function toggleSB(){sbOn=!sbOn;document.getElementById('sidebar').classList.toggle('off',!sbOn);}
function toggleDT(){dtOn=!dtOn;const dt=document.getElementById('detail');if(!dtOn){dt.classList.remove('on');dt.classList.add('shut');}else{dt.classList.remove('shut');}}
function updateBar(d){
  const on=d.nodes.filter(n=>n.status==='online').length;
  document.getElementById('bstats').classList.add('on');
  document.getElementById('bsn').textContent=d.nodes.length;
  document.getElementById('bson').textContent=on;
  document.getElementById('bsoff').textContent=d.nodes.length-on;
  document.getElementById('bsl').textContent=d.links.length;
  document.getElementById('sbct').textContent=d.nodes.length;
}
function buildSB(d){
  const sb=document.getElementById('sblist');
  sb.innerHTML='';
  if(!d.nodes.length){sb.innerHTML='<div class="sbempty">Sin dispositivos</div>';return;}
  d.nodes.forEach(n=>{
    const c=document.createElement('div');
    c.className='dcard';c.id='dc-'+n.name;
    const r=n.type==='router';
    c.innerHTML=`<div class="dcrow"><div class="dcico ${r?'r':'s'}">${r?'🔀':'🔗'}</div><div style="flex:1;min-width:0"><div class="dcname">${n.name}</div><div class="dcip">${n.ip}</div></div><div class="dcled"></div></div><div class="dcmeta"><div><div class="dmlbl">Hostname</div><div class="dmval">${n.hostname||'—'}</div></div><div><div class="dmlbl">Tipo</div><div class="dmval">${r?'Router':'Switch L2'}</div></div></div>`;
    c.onclick=()=>{document.querySelectorAll('.dcard').forEach(x=>x.classList.remove('sel'));c.classList.add('sel');selNode(n);};
    sb.appendChild(c);
  });
}
function draw(d){
  const wrap=document.getElementById('mapwrap');
  const W=wrap.clientWidth,H=wrap.clientHeight;
  const svg=d3.select('#topo').attr('width',W).attr('height',H);
  svg.selectAll('*').remove();
  svg.append('defs').html(`<filter id="sh"><feDropShadow dx="0" dy="3" stdDeviation="7" flood-color="rgba(0,0,0,.5)"/></filter><filter id="shsel"><feDropShadow dx="0" dy="4" stdDeviation="12" flood-color="rgba(37,99,235,.35)"/></filter><marker id="arr" markerWidth="8" markerHeight="8" refX="33" refY="4" orient="auto"><path d="M0,0 L0,8 L8,4 z" fill="#334155"/></marker>`);
  const nodes=d.nodes.map(n=>({...n}));
  const links=d.links.map(l=>({...l}));
  nodes.sort((a,b)=>{if(a.type==='router')return -1;if(b.type==='router')return 1;return a.name.localeCompare(b.name);});
  const total=nodes.length;
  const sp=Math.min(185,Math.max(130,(W-180)/(total-1||1)));
  const tw=sp*(total-1);
  const sx=(W-tw)/2;
  nodes.forEach((n,i)=>{n.fx=sx+i*sp;n.fy=H/2;});
  sim=d3.forceSimulation(nodes).force('link',d3.forceLink(links).id(n=>n.name).distance(sp)).alphaDecay(0.1).alpha(0.1);
  const lnk=svg.append('g').selectAll('line').data(links).enter().append('line').attr('stroke','#1e3050').attr('stroke-width',2.5).attr('stroke-linecap','round').attr('marker-end','url(#arr)');
  const ng=svg.append('g').selectAll('g').data(nodes).enter().append('g')
    .attr('cursor','pointer').attr('filter','url(#sh)')
    .on('click',(e,n)=>{document.querySelectorAll('.dcard').forEach(x=>x.classList.remove('sel'));const c=document.getElementById('dc-'+n.name);if(c){c.classList.add('sel');c.scrollIntoView({block:'nearest'});}selNode(n);})
    .on('mouseenter',function(){d3.select(this).attr('filter','url(#shsel)');d3.select(this).select('rect').attr('stroke-width',3);})
    .on('mouseleave',function(){d3.select(this).attr('filter','url(#sh)');d3.select(this).select('rect').attr('stroke-width',2);})
    .call(d3.drag().on('start',(e,n)=>{n.fx=n.x;n.fy=n.y;}).on('drag',(e,n)=>{n.fx=e.x;n.fy=e.y;sim.alpha(0.05).restart();}).on('end',()=>{}));
  ng.each(function(n){
    const g=d3.select(this);
    const w=n.type==='router'?114:102,h=n.type==='router'?48:38;
    if(n.type==='router')drawR(g,w,h);else drawS(g,w,h);
    g.append('text').attr('dy',n.type==='router'?40:30).attr('text-anchor','middle').attr('font-size',13).attr('font-weight',800).attr('fill','#e2e8f0').attr('font-family','DM Sans,system-ui,sans-serif').text(n.name);
    g.append('text').attr('dy',n.type==='router'?54:44).attr('text-anchor','middle').attr('font-size',10).attr('fill','#475569').attr('font-family','DM Mono,monospace').text(n.ip);
  });
  sim.on('tick',()=>{lnk.attr('x1',l=>l.source.x).attr('y1',l=>l.source.y).attr('x2',l=>l.target.x).attr('y2',l=>l.target.y);ng.attr('transform',n=>`translate(${n.x},${n.y})`);});
}
async function selNode(n){
  const dt=document.getElementById('detail');
  dt.classList.remove('shut');dt.classList.add('on');dtOn=true;
  const r=n.type==='router';
  document.getElementById('dico').innerHTML=`<div class="dheadico ${r?'r':'s'}">${r?'🔀':'🔗'}</div>`;
  document.getElementById('dhn').textContent=n.name;
  document.getElementById('dhip').textContent=n.ip;
  document.getElementById('dbody').innerHTML=`<div class="snmpl"><div class="snmlring"></div><span>Consultando via SNMP en tiempo real...</span></div>`;
  try{const res=await fetch('/api/device/'+n.ip);const d=await res.json();renderDet(d);}
  catch(e){document.getElementById('dbody').innerHTML=`<div style="color:var(--red);font-size:12px;padding:12px 0;font-weight:600">Error al consultar dispositivo</div>`;}
}
function renderDet(d){
  const uI=d.interfaces.filter(i=>i.status==='up').length;
  const tI=d.interfaces.length;
  const rows=d.interfaces.map(i=>`<tr><td class="ifname">${i.name}</td><td><span class="sdot ${i.status==='up'?'dup':'ddn'}"></span><span class="${i.status==='up'?'sup':'sdown'}">${i.status}</span></td><td><span class="spdtag">${i.speed}</span></td></tr>`).join('');
  document.getElementById('dbody').innerHTML=`
    <div class="mbanner"><div class="mtitle">${d.model||d.hostname}</div><div class="msub">IOS ${d.os_version||'—'}</div></div>
    <div class="isec"><div class="isech">Información del sistema</div>${ir('Hostname',d.hostname,'mo')}${ir('Tipo',d.type==='router'?'Router Cisco IOSv':'Switch L2 IOSv','')}${ir('Dirección IP',d.ip,'mo')}${ir('Tiempo activo',d.uptime,'')}${ir('Contacto',d.contact,'')}${ir('Ubicación',d.location,'')}${ir('Object ID',d.object_id?(d.object_id.length>24?d.object_id.substring(0,24)+'…':d.object_id):'—','mo')}</div>
    <div class="isec"><div class="isech">Interfaces <span style="color:var(--text3);font-weight:500;text-transform:none;letter-spacing:0;font-size:10px">${uI}/${tI} activas</span></div>${tI>0?`<table class="iftable"><thead><tr><th>Interfaz</th><th>Estado</th><th>Velocidad</th></tr></thead><tbody>${rows}</tbody></table>`:'<div style="color:var(--text3);font-size:11px;padding:6px 0">Sin interfaces</div>'}</div>
    <div class="isec"><div class="isech">Sistema operativo</div><div class="osbox">${d.full_description||'—'}</div></div>`;
}
function ir(l,v,c){const val=v&&v!=='—'?v:'—';return `<div class="irow"><span class="ik">${l}</span><span class="iv ${c}">${val}</span></div>`;}
</script>
</body>
</html>'''

if __name__ == '__main__':
    print("Iniciando en http://localhost:5000")
    app.run(debug=False, host='0.0.0.0', port=5000)
