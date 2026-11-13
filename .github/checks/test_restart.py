"""Restart, access list reload, CIDR deny, route overrides and state interoperability."""
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

ROOT = Path(os.environ.get("TRACKER_ROOT", Path(__file__).resolve().parents[2])).resolve()
BIN = os.environ.get("TRACKER_BINARY", str(ROOT / "yukitracker"))
with tempfile.TemporaryDirectory() as tmp:
    directory = Path(tmp)
    directory.chmod(0o777)  # the daemon drops privileges when CI runs as root
    state = directory / "state.jsonl"
    acl = directory / "allowed.txt"
    config = directory / "tracker.yaml"
    key = "01234567890123456789"
    other = "x"*20
    with socket.socket() as s:
        s.bind(("127.0.0.1",0))
        port = s.getsockname()[1]
    state.write_text('{"format":"yukitracker-state","version":1}\n' +
                     json.dumps(dict(info_hash=key.encode().hex(), completed=17))+"\n")
    acl.write_text(key.encode().hex()+"\n")
    yaml = (ROOT/"yukitracker.yaml").read_text().replace(":6969",f":{port}")
    yaml = yaml.replace("paths.health: /healthz","paths.health: /ready")
    yaml = yaml.replace('access.fullscrape: ["127.0.0.1/32", "::1/128"]','access.fullscrape: "192.0.2.1/32"')
    yaml=yaml.replace("diagnostics.log_entries: 0","diagnostics.log_entries: 4").replace("diagnostics.busy_entries: 0","diagnostics.busy_entries: 16")
    yaml += "\naccess.record: 127.0.0.1/32\naccess.diagnostics: 127.0.0.1/32\n"
    config.write_text(yaml + f"\nstate.file: {state}\nstate.save_interval: 1\naccess.whitelist: {acl}\n")
    def get(path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1",port,timeout=3)
        try:
            conn.request("GET", path, headers=headers or {})
            r=conn.getresponse()
            return r.status,r.read()
        finally:
            conn.close()
    def announce(h):
        return get("/announce?info_hash="+h+"&left=0&port=1337&compact=1")[1]
    for run in range(2):
        server = subprocess.Popen([BIN,"-f",config])
        try:
            for _ in range(100):
                try:
                    if get("/ready")[0]==200: break
                except OSError: time.sleep(.03)
            assert get("/healthz")[0]==404
            diag=json.loads(get("/api/v1/diagnostics/requests?limit=2")[1])
            assert len(diag["items"])==2 and diag["items"][1]["request"].startswith("GET /healthz ")
            busy=json.loads(get("/api/v1/diagnostics/busy-networks")[1])
            assert busy["prefix_bits"]==24 and busy["items"]==[]
            assert get("/api/v1/export/torrents")[0]==403
            assert json.loads(get("/api/v1/stats")[1])["completions"]==17
            if run == 0:
                announce(other)
                assert json.loads(get("/api/v1/stats")[1])["torrents"]==1
                acl.write_text(key.encode().hex()+"\n"+other.encode().hex()+"\n")
                server.send_signal(signal.SIGHUP)
                for _ in range(100):
                    announce(other)
                    if json.loads(get("/api/v1/stats")[1])["torrents"]==2: break
                    time.sleep(.02)
                assert json.loads(get("/api/v1/stats")[1])["torrents"]==2
                ino = state.stat().st_ino
                for _ in range(100):
                    if state.stat().st_ino != ino: break
                    time.sleep(.03)
                assert state.stat().st_ino != ino
        finally:
            server.terminate()
            assert server.wait(timeout=8)==0
        assert json.loads(state.read_text().splitlines()[1])["completed"]==17
    config.write_text(yaml.replace("export.min_interval: 0","export.min_interval: 3")
                      .replace("export.max_clients: 4096", "export.max_clients: 2")
                      .replace('access.fullscrape: "192.0.2.1/32"', 'access.fullscrape: "127.0.0.0/24"')
                      + "\naccess.proxy: 127.0.0.1/32\n")
    server=subprocess.Popen([BIN,"-f",config])
    try:
        for _ in range(100):
            try:
                if get("/ready")[0]==200: break
            except OSError: time.sleep(.03)
        assert get("/api/v1/export/torrents")[0]==200
        assert get("/api/v1/export/torrents")[0]==429
        export = "/api/v1/export/torrents"
        second = {"X-Forwarded-For": "127.0.0.2"}
        third = {"X-Forwarded-For": "127.0.0.3"}
        assert get(export, second)[0] == 200
        assert get(export, third)[0] == 429
        time.sleep(3.1)
        assert get(export, third)[0] == 200
        assert get(export, second)[0] == 200
        assert get(export, third)[0] == 429
        conn=http.client.HTTPConnection("127.0.0.1",port,timeout=3)
        conn.request("GET","/api/v1/stats",headers={"X-Forwarded-For":"127.0.0.1, 192.0.2.33"})
        assert conn.getresponse().status==403
        conn.close()
    finally:
        server.terminate()
        assert server.wait(timeout=8)==0
print("State restart, ACL reload, route override and CIDR tests passed")
