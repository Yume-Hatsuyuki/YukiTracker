"""Exercise the release binary over HTTP and BEP 15."""
import gzip
import http.client
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

ROOT = Path(os.environ.get("TRACKER_ROOT", Path(__file__).resolve().parents[2])).resolve()
BIN = os.environ.get("TRACKER_BINARY", str(ROOT / "yukitracker"))
with tempfile.TemporaryDirectory() as tmp:
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    config = Path(tmp) / "smoke.yml"
    sample = (ROOT / "yukitracker.yaml").read_text()
    config.write_text(sample.replace(":6969", f":{port}").replace("1800", "90").replace("360", "0"))
    bad = Path(tmp) / "invalid.yml"
    bad.write_text(config.read_text() + "tracker.fake: true\n")
    assert subprocess.run([BIN, "-C", "-f", bad], capture_output=True).returncode
    for key, good, invalid in (("http.read_timeout", 30, 0), ("http.write_timeout", 900, 86401), ("export.max_clients", 4096, 0)):
        bad.write_text(config.read_text().replace(f"{key}: {good}", f"{key}: {invalid}"))
        assert subprocess.run([BIN, "-C", "-f", bad], capture_output=True).returncode
    subprocess.run([BIN, "-C", "-f", config], check=True)
    server = subprocess.Popen([BIN, "-f", config])
    def get(path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
        try:
            conn.request("GET", path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.getheader("Content-Type"), resp.read()
        finally:
            conn.close()
    try:
        for attempt in range(100):
            try:
                if get("/healthz")[0] == 200:
                    break
            except OSError:
                time.sleep(.04)
        version = subprocess.check_output([BIN, "-v"], stderr=subprocess.STDOUT, text=True).splitlines()[0]
        health = json.loads(get("/healthz")[2])
        assert health["status"] == "ok" and version == "YukiTracker " + health["version"]
        assert json.loads(get("/api/v1/stats")[2])["version"] == health["version"]
        assert ('version="' + health["version"] + '"').encode() in get("/metrics")[2]
        assert get("/api/v1/export/torrents") == (200, "application/x-ndjson", b"")
        key = "abcdefghijklmnopqrst"
        query = f"?info_hash={key}&port=1337&left=0&compact=1"
        assert b"8:intervali90e" in get("/announce" + query)[2]
        assert key.encode() in get("/scrape?info_hash=" + key)[2]
        assert get("/another" + query)[0] == 404
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("127.0.0.1", port))
            sock.settimeout(3)
            sock.send(struct.pack("!QII", 0x41727101980, 0, 123))
            action, tid, cid = struct.unpack("!IIQ", sock.recv(128))
            assert (action, tid) == (0, 123)
            sock.send(struct.pack("!QII20s", cid, 2, 124, key.encode()))
            assert struct.unpack("!IIIII", sock.recv(128)) == (2, 124, 1, 0, 0)
        assert json.loads(get("/api/v1/stats")[2])["peers"]["seeders"] == 1
        assert b"yukitracker_torrents 1" in get("/metrics")[2]
        expected = dict(info_hash=key.encode().hex(), seeders=1, leechers=0, completed=0)
        status, mime, body = get("/api/v1/export/torrents")
        assert (status, mime, json.loads(body)) == (200, "application/x-ndjson", expected)
        body = get("/api/v1/export/torrents", {"Accept-Encoding": "gzip"})[2]
        assert json.loads(gzip.decompress(body)) == expected
        body = get("/api/v1/export/torrents", {"Accept-Encoding": "gzip;q=0"})[2]
        assert json.loads(body) == expected
        path = "/api/v1/stats/"
        assert json.loads(get(path+"top?by=seeders&limit=1")[2])["items"] == [expected]
        assert json.loads(get(path+"networks")[2])["items"] == [{"network": "127.0.0.0/24", "peers": 1}]
        assert get(path+"torrents?limit=1001")[0] == 400
        assert b"interval" in get("/announce"+query.replace(key, "z"*20))[2]
        first = json.loads(get(path+"torrents?limit=1")[2])
        assert first["items"] == [expected]
        last = json.loads(get(path+"torrents?limit=1&cursor="+first["next_cursor"])[2])
        assert last["items"][0]["info_hash"] == ("7a"*20) and last["next_cursor"] is None
        # Prime both views, then change an existing peer without changing torrent count.
        assert json.loads(get("/api/v1/stats")[2])["peers"]["seeders"] == 2
        assert b'role="seeder"} 2' in get("/metrics")[2]
        assert b"interval" in get("/announce"+query.replace("left=0","left=1"))[2]
        assert json.loads(get("/api/v1/stats")[2])["peers"] == {"total":2,"seeders":1,"leechers":1}
        assert b'role="leecher"} 1' in get("/metrics")[2]
        assert b"interval" in get("/announce"+query+"&event=completed")[2]
        assert b"yukitracker_completions_total 1" in get("/metrics")[2]
        assert b"interval" in get("/announce"+query+"&event=stopped")[2]
        summary = json.loads(get("/api/v1/stats")[2])
        assert summary["peers"]["total"] == summary["peers_by_family"]["ipv4"] == 1
        assert summary["completions"] == 1
    finally:
        server.terminate()
        assert server.wait(timeout=5) == 0
print("YukiTracker HTTP/UDP smoke passed")
