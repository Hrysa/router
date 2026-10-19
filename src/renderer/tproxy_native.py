"""Only invoked inside a fresh `unshare -n` by the ignored native Rust test."""
import json
import os
import socket
import subprocess
import sys
import time


def run(*args):
    return subprocess.check_output(args, text=True)


client = subprocess.Popen(["unshare", "-n", "sleep", "60"])
try:
    for _ in range(100):
        if os.readlink(f"/proc/{client.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
            break
        time.sleep(0.01)
    else:
        raise AssertionError("client network namespace was not created")

    def client_run(*args):
        return run("nsenter", "-t", str(client.pid), "-n", *args)

    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "lan0", "type", "veth", "peer", "name", "client0")
    run("ip", "link", "set", "client0", "netns", str(client.pid))
    run("ip", "addr", "add", "10.88.0.1/24", "dev", "lan0")
    run("ip", "link", "set", "lan0", "up")
    run("ip", "link", "add", "wan0", "type", "dummy")
    run("ip", "link", "set", "wan0", "up")
    run("ip", "route", "add", "198.18.0.0/15", "dev", "wan0")
    run("sysctl", "-qw", "net.ipv4.ip_forward=1")
    for name in ["all", "default", "lan0"]:
        run("sysctl", "-qw", f"net.ipv4.conf.{name}.rp_filter=0")
    client_run("ip", "link", "set", "lo", "up")
    client_run("ip", "addr", "add", "10.88.0.2/24", "dev", "client0")
    client_run("ip", "link", "set", "client0", "up")
    client_run("ip", "route", "add", "default", "via", "10.88.0.1")
    run("ip", "rule", "add", "priority", "89", "fwmark", "1", "lookup", "1")
    run("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "1")

    listener = socket.socket()
    listener.setsockopt(socket.SOL_IP, 19, 1)  # IP_TRANSPARENT
    listener.bind(("0.0.0.0", 12345))
    listener.listen(8)
    listener.settimeout(0.3)
    run("nft", "-j", "-c", "-f", sys.argv[1])
    run("nft", "-j", "-f", sys.argv[1])
    # A counter-only observation rule preserves the base-chain Drop policy and
    # proves unmatched candidates really reach forward before the default drop.
    run("nft", "add", "rule", "inet", "filter", "forward", "tcp", "dport", "86",
        "counter", "comment", '"native default-drop observation"')

    query = """
import json,socket,sys,time
s=socket.socket(); s.settimeout(0.45)
started=time.monotonic()
result=s.connect_ex((sys.argv[2] if len(sys.argv)>2 else '198.18.0.1', int(sys.argv[1])))
print(json.dumps({'result':result, 'elapsed':time.monotonic()-started}))
s.close()
"""
    for port, expected in [(81, "drop"), (82, "reject"), (83, "proxy"),
                           (84, "forward"), (85, "forward"), (86, "default-drop")]:
        result = json.loads(client_run("python3", "-c", query, str(port)))
        if expected == "proxy":
            assert result["result"] == 0, (port, result)
            connection, _ = listener.accept()
            assert connection.getsockname() == ("198.18.0.1", port)
            connection.close()
        else:
            assert result["result"] != 0, (port, result)
            if expected == "reject":
                assert result["elapsed"] < 0.4, result
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                pass
            else:
                connection.close()
                raise AssertionError(f"port {port} unexpectedly reached proxy")
        print(port, expected, result)

    rules = json.loads(run("nft", "-j", "list", "table", "inet", "filter"))["nftables"]
    counts = {}
    for entry in rules:
        rule = entry.get("rule", {})
        for expression in rule.get("expr", []):
            if "counter" in expression:
                counts[(rule["chain"], rule.get("comment", "").split(" ")[0])] = expression["counter"]["packets"]
    for chain, label in [("forward", "[1]"), ("forward", "[2]"),
                         ("tproxy_policy", "[3]"), ("forward", "[4]"),
                         ("forward", "[5]"), ("tproxy_dispatch", "[8]")]:
        assert counts.get((chain, label), 0) > 0, (chain, label, counts)
    assert counts.get(("forward", "[3]"), 0) == 0, counts
    for label in ["[1]", "[2]"]:
        assert counts.get(("tproxy_policy", label), 0) == 0, counts
    assert counts.get(("forward", "native"), 0) > 0, counts
    # A non-candidate still reaches the existing forward reject rule.
    run("ip", "route", "add", "203.0.113.0/24", "dev", "wan0")
    ordinary = json.loads(client_run("python3", "-c", query, "82", "203.0.113.1"))
    assert ordinary["result"] != 0 and ordinary["elapsed"] < 0.4, ordinary

    # With an accepting forward default, an otherwise unmatched candidate is admitted.
    run("nft", "-j", "-c", "-f", sys.argv[2])
    run("nft", "-j", "-f", sys.argv[2])
    accepted = json.loads(client_run("python3", "-c", query, "86"))
    assert accepted["result"] == 0, accepted
    connection, _ = listener.accept()
    connection.close()

    # Router-owned destinations keep input policy; the proxy-delivery exception
    # must not open local services just because a proxy mark/socket is present.
    run("ip", "addr", "add", "198.18.0.1/32", "dev", "lo")
    local = json.loads(client_run("python3", "-c", query, "83"))
    assert local["result"] != 0, local
    print("isolated TPROXY admission, forward rejection, default policies, and local-input isolation passed")
finally:
    client.terminate()
    client.wait(timeout=5)
