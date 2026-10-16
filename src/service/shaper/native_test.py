"""Test-only fixture. Invoked inside the self-isolating Rust native test."""
import json
import multiprocessing
import os
import signal
import socket
import select
import subprocess
import sys
import time

def timeout(*_):
    raise TimeoutError("isolated traffic fixture exceeded 45 seconds")
signal.signal(signal.SIGALRM, timeout)
signal.alarm(45)
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)

receiver_code = r'''
import json, os, select, socket, sys, threading
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 9000))
down = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
down.bind(('0.0.0.0', 9002))
down.setblocking(False)
registered = []
down_stop = threading.Event()
def download_flood():
    while not down_stop.is_set():
        for tag, address in registered:
            try: down.sendto(tag * 1000, address)
            except BlockingIOError: pass
counts = {'A': 0, 'B': 0}
sources = set()
print(os.getpid(), flush=True)
while True:
    ready, _, _ = select.select([sock, down, sys.stdin], [], [], 1)
    if sys.stdin in ready:
        command = sys.stdin.readline().strip()
        if command == 'REPORT':
            print(json.dumps({'counts':counts, 'sources':sorted(sources)}), flush=True)
            counts = {'A':0, 'B':0}; sources = set()
        elif command == 'DOWNLOAD_START':
            assert len(registered) == 5, registered
            assert {address[0] for _, address in registered} == {'10.231.0.1'}, registered
            threading.Thread(target=download_flood, daemon=True).start()
            print('STARTED', flush=True)
        elif command == 'DOWNLOAD_STOP':
            down_stop.set(); print('STOPPED', flush=True)
        elif not command or command == 'STOP':
            break
    if down in ready:
        data, source = down.recvfrom(65535)
        if data[:1] == b'R': registered.append((data[1:2], source))
    if sock in ready:
        data, source = sock.recvfrom(65535)
        if data[:1] == b'P': sock.sendto(data, source)
        elif data[:1] in (b'A', b'B'):
            counts[data[:1].decode()] += len(data)
            sources.add(source[0])
'''
receiver = subprocess.Popen(['unshare', '--net', 'python3', '-u', '-c', receiver_code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
workers = []
try:
    pid = int(receiver.stdout.readline())
    run('ip', 'link', 'add', 'wan0', 'type', 'veth', 'peer', 'name', 'peer0')
    run('ip', 'link', 'set', 'peer0', 'netns', str(pid))
    run('ip', 'address', 'add', '10.231.0.1/24', 'dev', 'wan0')
    run('ip', 'address', 'add', '10.231.0.3/24', 'dev', 'wan0')
    run('ip', 'link', 'set', 'wan0', 'up')
    run('nsenter', '-t', str(pid), '-n', 'ip', 'address', 'add', '10.231.0.2/24', 'dev', 'peer0')
    run('nsenter', '-t', str(pid), '-n', 'ip', 'link', 'set', 'peer0', 'up')
    # Real SNAT makes both hosts appear as one address on the wire. Payload tags
    # let the receiver measure the original hosts independently of their ports.
    rules = {'nftables': [
        {'add': {'table': {'family':'ip', 'name':'shaper_test_nat'}}},
        {'add': {'chain': {'family':'ip', 'table':'shaper_test_nat', 'name':'postrouting', 'type':'nat', 'hook':'postrouting', 'prio':100, 'policy':'accept'}}},
        {'add': {'rule': {'family':'ip', 'table':'shaper_test_nat', 'chain':'postrouting', 'expr':[
            {'match': {'left': {'meta':{'key':'oifname'}}, 'op':'==', 'right':'wan0'}}, {'masquerade':None}
        ]}}}
    ]}
    subprocess.run(['nft', '-j', '-f', '-'], input=json.dumps(rules), text=True, check=True)
    print('READY', flush=True)
    assert sys.stdin.readline().strip() == 'GO'
    def report():
        receiver.stdin.write('REPORT\n'); receiver.stdin.flush()
        return json.loads(receiver.stdout.readline())
    def flood(address, tag, flows, stop):
        sockets = []
        for _ in range(flows):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((address, 0)); sock.setblocking(False); sockets.append(sock)
        payload = tag * 1000
        while not stop.is_set():
            for sock in sockets:
                try: sock.sendto(payload, ('10.231.0.2', 9000))
                except BlockingIOError: pass
        for sock in sockets: sock.close()
    stops = [multiprocessing.Event(), multiprocessing.Event()]
    for address, tag, flows, stop in [('10.231.0.1', b'A', 4, stops[0]), ('10.231.0.3', b'B', 1, stops[1])]:
        process = multiprocessing.Process(target=flood, args=(address, tag, flows, stop))
        process.start(); workers.append(process)
    time.sleep(.5); report()
    start = time.monotonic()
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(('10.231.0.1', 0)); probe.settimeout(.5)
    delays = []
    for number in range(10):
        payload = b'P' + bytes([number])
        before = time.monotonic(); probe.sendto(payload, ('10.231.0.2', 9000))
        assert probe.recv(128) == payload
        delays.append(time.monotonic() - before); time.sleep(.1)
    time.sleep(max(0, 3 - (time.monotonic() - start)))
    both = report(); elapsed = time.monotonic() - start
    share = both['counts']['A'] / sum(both['counts'].values())
    assert .30 < share < .70, ('host fairness failed', both, share)
    assert both['sources'] == ['10.231.0.1'], ('SNAT was not exercised', both)
    stops[0].set(); workers[0].join(3)
    time.sleep(.3); report(); start_solo = time.monotonic(); time.sleep(2)
    solo = report(); solo_elapsed = time.monotonic() - start_solo
    gain = (solo['counts']['B'] / solo_elapsed) / (both['counts']['B'] / elapsed)
    assert gain > 1.4, ('idle bandwidth not reused', both, solo, gain)
    assert max(delays) < .5, delays
    for stop in stops: stop.set()
    for worker in workers: worker.join(3)
    # Download replies traverse the WAN ingress IFB before reverse SNAT. CAKE
    # must recover the two original destination hosts from conntrack here too.
    sinks = []
    for address, tag, flows in [('10.231.0.1', b'A', 4), ('10.231.0.3', b'B', 1)]:
        for _ in range(flows):
            sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sink.bind((address, 0)); sink.sendto(b'R' + tag, ('10.231.0.2', 9002)); sinks.append(sink)
    time.sleep(.2)
    receiver.stdin.write('DOWNLOAD_START\n'); receiver.stdin.flush()
    assert receiver.stdout.readline().strip() == 'STARTED'
    downloaded = {'A':0, 'B':0}; start_down = time.monotonic()
    while time.monotonic() - start_down < 3:
        ready, _, _ = select.select(sinks, [], [], .1)
        for sink in ready:
            data = sink.recv(65535)
            downloaded[data[:1].decode()] += len(data)
    receiver.stdin.write('DOWNLOAD_STOP\n'); receiver.stdin.flush()
    assert receiver.stdout.readline().strip() == 'STOPPED'
    down_share = downloaded['A'] / sum(downloaded.values())
    assert .30 < down_share < .70, ('download NAT host fairness failed', downloaded, down_share)
    for sink in sinks: sink.close()
    print(json.dumps({'host_A_share':share, 'download_host_A_share':down_share, 'solo_host_B_gain':gain, 'max_probe_delay_ms':max(delays)*1000, 'contended_Mbit_s':sum(both['counts'].values())*8/elapsed/1e6}), flush=True)
    assert sys.stdin.readline().strip() == 'DONE'
finally:
    for worker in workers:
        if worker.is_alive(): worker.terminate()
        worker.join(3)
    receiver.terminate()
    try: receiver.wait(3)
    except subprocess.TimeoutExpired: receiver.kill(); receiver.wait()
