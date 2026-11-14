#!/usr/bin/env python3
"""Native acceptance harness: a stand-in policy proxy for WSL test runs.

The production policy proxy is the TypeScript module in src/sandbox/egress.
This harness implements the same wire protocol (PIEGRESS1 auth frame, HTTP
forward proxy + CONNECT, SOCKS5 CONNECT, host/port allowlist checked before
connect) so the Linux bridge and sandbox can be exercised end to end on a
host without Node. It exists only for native acceptance evidence; module
semantics are covered by the TypeScript unit tests.

usage: egress-harness.py <listen-port> <lease> <credential> <allowed-host[,host:port...]> <events-file>
"""
import json
import socket
import sys
import threading


def parse_allowlist(text):
    rules = []
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        if token.startswith("["):
            host, _, rest = token[1:].partition("]")
            port = int(rest[1:]) if rest.startswith(":") else None
        elif ":" in token:
            host, _, port_text = token.rpartition(":")
            port = int(port_text)
        else:
            host, port = token, None
        rules.append((host.lower(), port))
    return rules


def allowed(rules, host, port):
    host = host.lower().strip("[]")
    for rule_host, rule_port in rules:
        if rule_host == host and (rule_port is None or rule_port == port):
            return True
    return False


def relay(left, right):
    sockets = [left, right]
    try:
        while True:
            readable, _, _ = select(sockets, [], [], 30)
            if not readable:
                return
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                target = right if source is left else left
                target.sendall(data)
    except OSError:
        return
    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass


def select(sockets, _w, _x, timeout):
    import select as select_module
    return select_module.select(sockets, [], [], timeout)


def read_line(connection, limit=4096):
    data = b""
    while not data.endswith(b"\n"):
        chunk = connection.recv(1)
        if not chunk:
            raise ConnectionError("eof")
        data += chunk
        if len(data) > limit:
            raise ConnectionError("line too long")
    return data.decode("utf-8", "strict").strip()


def read_exact(connection, count):
    data = b""
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise ConnectionError("eof")
        data += chunk
    return data


def serve_http(connection, lease, buffered, rules, events):
    data = buffered
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(65536)
        if not chunk:
            return
        data += chunk
        if len(data) > 65536:
            return
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    method, target, _version = (lines[0].split(" ") + [""])[:3]
    if method == "CONNECT":
        authority = target
        if authority.startswith("["):
            host, _, rest2 = authority[1:].partition("]")
            port = int(rest2[1:]) if rest2.startswith(":") else 443
        elif ":" in authority:
            host, _, port_text = authority.rpartition(":")
            port = int(port_text)
        else:
            host, port = authority, 443
    else:
        if not target.startswith("http://"):
            connection.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nforbidden")
            events.append({"result": "denied", "target": target, "reason": "scheme"})
            return
        authority = target[len("http://"):].split("/", 1)[0]
        host, _, port_text = authority.rpartition(":") if ":" in authority else (authority, "", "")
        port = int(port_text) if port_text else 80
    events.append({"result": "check", "lease": lease, "host": host, "port": port})
    if not allowed(rules, host, port):
        events.append({"result": "denied", "host": host, "port": port})
        connection.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nforbidden")
        return
    try:
        upstream = socket.create_connection((host, port), timeout=10)
    except OSError:
        connection.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 7\r\n\r\nfailed")
        return
    events.append({"result": "connected", "host": host, "port": port})
    if method == "CONNECT":
        connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        relay(connection, upstream)
        return
    path = "/" + target[len("http://") + len(authority):].lstrip("/")
    rewritten = [f"{method} {path} HTTP/1.1"] + [
        line
        for line in lines[1:]
        if line.split(":", 1)[0].strip().lower()
        not in {"proxy-authorization", "proxy-connection", "connection", "keep-alive"}
    ]
    rewritten.append("Connection: close")
    upstream.sendall(("\r\n".join(rewritten) + "\r\n\r\n").encode("latin1") + rest)
    relay(connection, upstream)


def serve_socks(connection, lease, buffered, rules, events):
    data = buffered
    while len(data) < 2:
        data += read_exact(connection, 2 - len(data))
    methods = data[1]
    while len(data) < 2 + methods:
        data += read_exact(connection, 2 + methods - len(data))
    data = data[2 + methods:]
    connection.sendall(b"\x05\x00")
    while len(data) < 4:
        data += read_exact(connection, 4 - len(data))
    atyp = data[3]
    if atyp == 1:
        needed = 10
    elif atyp == 3:
        while len(data) < 5:
            data += read_exact(connection, 5 - len(data))
        needed = 5 + data[4] + 2
    elif atyp == 4:
        needed = 22
    else:
        connection.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
        return
    while len(data) < needed:
        data += read_exact(connection, needed - len(data))
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, data[4:8])
        port = int.from_bytes(data[8:10], "big")
    elif atyp == 3:
        length = data[4]
        host = data[5:5 + length].decode("utf8", "strict")
        port = int.from_bytes(data[5 + length:5 + length + 2], "big")
    else:
        host = socket.inet_ntop(socket.AF_INET6, data[4:20])
        port = int.from_bytes(data[20:22], "big")
    rest = data[needed:]
    events.append({"result": "check", "lease": lease, "host": host, "port": port})
    if not allowed(rules, host, port):
        events.append({"result": "denied", "host": host, "port": port})
        connection.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        return
    try:
        upstream = socket.create_connection((host, port), timeout=10)
    except OSError:
        connection.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        return
    events.append({"result": "connected", "host": host, "port": port})
    connection.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    if rest:
        upstream.sendall(rest)
    relay(connection, upstream)


def handle(connection, expected_lease, credential, rules, events):
    try:
        line = read_line(connection)
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != "PIEGRESS1":
            events.append({"result": "auth-failed", "line": line})
            return
        lease, secret = parts[1], parts[2]
        if lease != expected_lease or secret != credential:
            events.append({"result": "auth-failed", "lease": lease})
            return
        first = connection.recv(1, socket.MSG_PEEK)
        if not first:
            return
        if first == b"\x05":
            serve_socks(connection, lease, b"", rules, events)
        else:
            serve_http(connection, lease, b"", rules, events)
    except (ConnectionError, OSError, ValueError, IndexError):
        return
    finally:
        try:
            connection.close()
        except OSError:
            pass


def main():
    port = int(sys.argv[1])
    lease = sys.argv[2]
    credential = sys.argv[3]
    rules = parse_allowlist(sys.argv[4])
    events_path = sys.argv[5]
    events = []
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(64)
    print(f"harness listening on 127.0.0.1:{port}", flush=True)

    def flush_events():
        with open(events_path, "a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")
        events.clear()

    try:
        while True:
            connection, _ = listener.accept()
            thread = threading.Thread(
                target=handle,
                args=(connection, lease, credential, rules, events),
                daemon=True,
            )
            thread.start()
            flush_events()
    except KeyboardInterrupt:
        flush_events()


if __name__ == "__main__":
    main()
