# Invoked exclusively inside a fresh `unshare --net` namespace by the Rust test.
import json, socket, struct, subprocess, sys, time, ipaddress

def run(*args, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stderr}")
    return result.stdout

def nft(document, check=False):
    args = ['nft', '-j'] + (['-c'] if check else []) + ['-f', '-']
    run(*args, data=json.dumps(document))

rules = json.load(open(sys.argv[1]))
updates = json.load(open(sys.argv[2]))
try:
    nft(rules, check=True)
except RuntimeError:
    for command in rules['nftables']:
        try:
            nft({'nftables': [command]})
        except RuntimeError as error:
            raise RuntimeError(f"Command: {command}\n{error}")
    raise
nft(rules)
for update in updates:
    nft(update, check=True)
    nft(update)
# Verify atomic replacement kept all buckets and can recover after all-down.
nft(updates[0])
for strict in [False, True]:
    name = 'wg_1_' + ('strict' if strict else 'normal')
    listing = json.loads(run('nft', '-j', 'list', 'map', 'inet', 'mangle', name))
    mapped = next(item['map'] for item in listing['nftables'] if 'map' in item)
    assert len(mapped['elem']) == 256, mapped

run('ip', 'link', 'set', 'lo', 'up')
for name in ['wan0', 'wan1']:
    run('ip', 'link', 'add', name, 'type', 'dummy')
    run('ip', 'link', 'set', name, 'up')
run('ip', 'addr', 'add', '203.0.113.2/29', 'dev', 'wan0')
run('ip', 'addr', 'add', '192.0.2.2/24', 'dev', 'wan1')
run('ip', 'link', 'add', 'lan0', 'type', 'veth', 'peer', 'name', 'client')
for name in ['lan0', 'client']:
    run('ip', 'link', 'set', name, 'up')
run('ip', 'addr', 'add', '192.168.0.1/23', 'dev', 'lan0')
for key, value in [('ip_forward', '1'), ('conf/all/rp_filter', '0'), ('conf/default/rp_filter', '0'), ('conf/lan0/rp_filter', '0')]:
    open('/proc/sys/net/ipv4/' + key, 'w').write(value)
for table, name, gateway, subnet in [(100, 'wan0', '203.0.113.1', '203.0.113.0/29'), (101, 'wan1', '192.0.2.1', '192.0.2.0/24')]:
    run('ip', 'route', 'add', subnet, 'dev', name, 'table', str(table))
    run('ip', 'route', 'add', 'default', 'via', gateway, 'dev', name, 'table', str(table))
    run('ip', 'rule', 'add', 'priority', '110', 'fwmark', str(table << 16) + '/4294901760', 'table', str(table))
    run('ip', 'neigh', 'replace', gateway, 'lladdr', '02:00:00:00:00:01', 'nud', 'permanent', 'dev', name)
# Both strict and preserving group modes must route and probe through the
# selected table. Strict marks are paired with their normal buckets.
normal = updates[0]['nftables'][1]['add']['element']['elem']
strict = updates[0]['nftables'][3]['add']['element']['elem']
for table, name in [(100, 'wan0'), (101, 'wan1')]:
    index = next(i for i, (_, mark) in enumerate(normal) if mark == table << 16)
    mark = strict[index][1]
    run('ip', 'rule', 'add', 'priority', '90', 'fwmark', str(mark) + '/4294901760', 'table', str(table))
    run('ip', 'rule', 'add', 'priority', '91', 'fwmark', str(mark) + '/4294901760', 'unreachable')
    lookup = json.loads(run('ip', '-j', '-N', '-4', 'route', 'get', '1.1.1.1', 'mark', str(mark), 'oif', name))[0]
    assert lookup['dev'] == name and int(lookup['table']) == table and lookup.get('prefsrc'), lookup
run('ip', 'route', 'add', 'default', 'via', '192.0.2.1', 'dev', 'wan1')
# Count only packets that passed routerd's forward guards and user firewall.
run('nft', 'add', 'table', 'inet', 'group_test')
run('nft', 'add', 'chain', 'inet', 'group_test', 'forward', '{ type filter hook forward priority 20; policy accept; }')
for name in ['wan0', 'wan1']:
    run('nft', 'add', 'rule', 'inet', 'group_test', 'forward', 'oifname', name, 'counter')

def counts():
    listing = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'group_test', 'forward'))
    return [next(expr['counter']['packets'] for expr in item['rule']['expr'] if 'counter' in expr) for item in listing['nftables'] if 'rule' in item]

def checksum(data):
    words = struct.unpack('!%dH' % (len(data)//2), data)
    result = sum(words)
    while result >> 16: result = (result & 65535) + (result >> 16)
    return ~result & 65535

mac = lambda name: bytes.fromhex(json.loads(run('ip', '-j', 'link', 'show', 'dev', name))[0]['address'].replace(':', ''))
lan_mac, client_mac = mac('lan0'), mac('client')
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
raw.bind(('client', 0))
def send(port, client=0, destination='198.51.100.9'):
    address = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('192.168.0.2')) + client))
    src, dst = socket.inet_aton(address), socket.inet_aton(destination)
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 29, port, 0, 64, 17, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    udp = struct.pack('!HHHH', port, 9999, 9, 0) + b'x'
    raw.send(lan_mac + client_mac + b'\x08\x00' + header + udp)

# Different ports and destinations from one client must all use one WAN.
before = counts()
for index in range(100): send(10000 + index, 450, f'198.51.100.{index + 1}')
time.sleep(.1)
after = counts()
assert [a-b for a,b in zip(after,before)] in ([100,0], [0,100]), (before,after)
before = counts()
# Weights distribute client IPs, rather than connections from a single client.
for index in range(400): send(20000 + index, index)
time.sleep(.2)
after = counts()
delta = [a-b for a,b in zip(after, before)]
assert sum(delta) == 400, delta
normal = updates[0]['nftables'][1]['add']['element']['elem']
wan0_slots = sum(mark == 100 << 16 for _, mark in normal)
if wan0_slots == 128:
    assert delta == [200, 200], delta
    # Every consecutive pair alternates, including .255 -> next subnet .0.
    for client in [0, 100, 252, 253, 254, 255, 256]:
        before = counts(); send(40000 + client, client); send(41000 + client, client + 1)
        time.sleep(.01)
        after = counts()
        assert [a-b for a,b in zip(after,before)] == [1,1], (client,before,after)
else:
    assert wan0_slots == 192 and delta == [300, 100], (wan0_slots, delta)
# Find a flow pinned to WAN0, then remove it from selection. It must stay pinned.
pinned = None
for port in range(30000, 30020):
    before = counts(); send(port, port - 30000); time.sleep(.01); after = counts()
    if after[0] > before[0]: pinned = (port, port - 30000); break
assert pinned is not None
only_wan1 = json.loads(json.dumps(updates[0]))
for command in only_wan1['nftables']:
    if 'add' in command:
        elements = command['add']['element']['elem']
        # Smooth 3:1 buckets contain both marks; WAN1 has the larger normal
        # mark, but strict marks need the matching bucket index.
        normal = updates[0]['nftables'][1]['add']['element']['elem']
        index = next(i for i, (_, mark) in enumerate(normal) if mark == 101 << 16)
        chosen = elements[index][1]
        for element in elements: element[1] = chosen
nft(only_wan1)
before = counts(); send(*pinned); send(31000); time.sleep(.05); after = counts()
assert [a-b for a,b in zip(after,before)] == [1,1], (before,after)
# All-down denies new flows; established pinned flows remain untouched.
nft(updates[1])
before = counts(); send(32000); send(*pinned); time.sleep(.05); after = counts()
assert [a-b for a,b in zip(after,before)] == [1,0], (before,after)
# Removing the selected route must not leak a pinned flow via main/WAN1.
run('ip', 'route', 'del', 'default', 'table', '100')
before = counts(); send(*pinned); time.sleep(.05); after = counts()
assert after == before, (before,after)
print('Verified source-IP affinity across ports/destinations, exact even/weighted modulo splits, connection stickiness, map failover, all-down blocking and no main-route leakage:', delta)
