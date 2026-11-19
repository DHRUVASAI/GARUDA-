"""GARUDA v3 Multi-Protocol Real Device Discovery Engine.
Resolves real human-readable device names using a 5-layer pipeline:
  1. mDNS / Bonjour (zeroconf) -> Apple iPhones/Macs, Chromecasts, Printers, Linux hosts
  2. SSDP / UPnP XML (<friendlyName>, <manufacturer>, <modelName>) -> Routers, Smart TVs, Speakers
  3. Sniffed DHCP Option 12 Hostnames (from live IDS sniffer)
  4. NetBIOS Node Status (UDP 137) + Reverse DNS (gethostbyaddr)
  5. Expanded IEEE OUI Database + Honest Randomized Private MAC detection
"""

import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from .network_detector import normalize_mac
from .oui_db import infer_device_type_from_vendor_or_name, lookup_mac_vendor

MDNS_SERVICES = [
    "_apple-mobdev2._tcp.local.",
    "_companion-link._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_workstation._tcp.local.",
    "_smb._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_http._tcp.local.",
    "_hap._tcp.local.",
    "_spotify-connect._tcp.local.",
]


def discover_mdns_names(timeout: float = 1.6) -> Dict[str, Tuple[str, str]]:
    """Browse mDNS/Bonjour services and return {ip: (friendly_name, os_or_service_hint)}."""
    found: Dict[str, Tuple[str, str]] = {}
    try:
        from zeroconf import ServiceBrowser, Zeroconf  # type: ignore
    except ImportError:
        return found

    class _Listener:
        def remove_service(self, zc, stype, name):
            pass

        def update_service(self, zc, stype, name):
            self.add_service(zc, stype, name)

        def add_service(self, zc, stype, name):
            try:
                info = zc.get_service_info(stype, name, timeout=500)
                if not info:
                    return
                addrs = info.parsed_addresses()
                clean_inst = name.split("." + stype)[0].strip()
                clean_server = (info.server or "").replace(".local.", "").strip()
                props = {
                    (k.decode("utf-8", "ignore") if isinstance(k, bytes) else str(k)):
                    (v.decode("utf-8", "ignore") if isinstance(v, bytes) else str(v))
                    for k, v in (info.properties or {}).items()
                }
                friendly = props.get("fn") or props.get("md") or clean_inst or clean_server
                friendly = re.sub(r"\s*\[[0-9a-fA-F:]{17}\]\s*", "", friendly).strip()
                hint = props.get("model") or props.get("md") or stype.split(".")[0].lstrip("_")
                for ip in addrs:
                    if "." in ip and not ip.startswith("127.") and friendly:
                        if ip not in found or len(friendly) > len(found[ip][0]):
                            found[ip] = (friendly, hint)
            except Exception:
                pass

    zc = None
    try:
        zc = Zeroconf()
        listener = _Listener()
        for svc in MDNS_SERVICES:
            ServiceBrowser(zc, svc, listener)
        time.sleep(timeout)
    except Exception:
        pass
    finally:
        if zc:
            try:
                zc.close()
            except Exception:
                pass
    return found


def parse_ssdp_xml(xml_text: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract (friendlyName, model/manufacturer hint) from a UPnP device descriptor XML."""
    try:
        root = ET.fromstring(xml_text)
        friendly = None
        mfr = None
        model = None
        for el in root.iter():
            tag = el.tag.split("}")[-1] if "}" in el.tag else el.tag
            text = (el.text or "").strip()
            if not text:
                continue
            if tag == "friendlyName" and not friendly:
                friendly = text
            elif tag == "manufacturer" and not mfr:
                mfr = text
            elif tag == "modelName" and not model:
                model = text
        hint = " ".join(p for p in (mfr, model) if p).strip() or None
        return friendly, hint
    except Exception:
        return None, None


def discover_ssdp_names(timeout: float = 1.2) -> Dict[str, Tuple[str, str]]:
    """Send UPnP SSDP M-SEARCH multicast and pull real friendlyName from responding routers/TVs."""
    found: Dict[str, Tuple[str, str]] = {}
    locations: Dict[str, str] = {}
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("utf-8")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(msg, ("239.255.255.250", 1900))
        t_end = time.monotonic() + timeout
        while time.monotonic() < t_end:
            try:
                data, addr = sock.recvfrom(4096)
                text = data.decode("utf-8", errors="ignore")
                m_loc = re.search(r"LOCATION:\s*(http://[^\r\n]+)", text, re.IGNORECASE)
                if m_loc and addr[0] not in locations:
                    locations[addr[0]] = m_loc.group(1).strip()
            except socket.timeout:
                break
            except Exception:
                break
        sock.close()
    except Exception:
        return found

    def _fetch(item):
        ip, url = item
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "GARUDA/3.0"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                body = resp.read(32768).decode("utf-8", errors="ignore")
                fn, hint = parse_ssdp_xml(body)
                if fn:
                    return ip, fn, hint or "UPnP Device"
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for res in ex.map(_fetch, locations.items()):
            if res:
                found[res[0]] = (res[1], res[2])

    return found


def query_netbios_name(ip: str, timeout: float = 0.4) -> Optional[str]:
    """Send UDP 137 NetBIOS NBSTAT wildcard query to resolve Windows/Samba computer names."""
    try:
        packet = (
            b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
            b"\x00\x21\x00\x01"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 57 and data[56] > 0 and len(data) >= 72:
            raw_name = data[57:72].decode("ascii", errors="ignore").strip()
            if raw_name and not raw_name.startswith("\x00"):
                return raw_name
    except Exception:
        pass
    return None


def _ping_host(ip: str) -> Optional[int]:
    sys_name = platform.system().lower()
    if sys_name == "windows":
        cmd = ["ping", "-n", "1", "-w", "300", ip]
    elif sys_name == "darwin":
        cmd = ["ping", "-c", "1", "-W", "300", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    t0 = time.perf_counter()
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=1.0, check=False)
        if res.returncode == 0:
            return max(1, int((time.perf_counter() - t0) * 1000))
    except Exception:
        pass
    return None


def read_os_arp_table() -> List[Tuple[str, str]]:
    """Parse OS ARP / neighbor cache into [(ip, mac), ...]."""
    entries: Dict[str, str] = {}
    sys_name = platform.system().lower()
    if sys_name == "linux":
        out = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=3, check=False).stdout
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]{17})", line)
            if m:
                ip, mac = m.group(1), normalize_mac(m.group(2))
                if not mac.startswith(("FF:FF:FF", "01:00:5E", "33:33")):
                    entries[ip] = mac
    else:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3, check=False).stdout
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)[^0-9a-fA-F]*(([0-9a-fA-F]{1,2}[-:]){5}[0-9a-fA-F]{1,2})", line)
            if m:
                ip, mac = m.group(1), normalize_mac(m.group(2))
                if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") and not mac.startswith(("01:00:5E", "33:33")):
                    entries[ip] = mac
    return list(entries.items())


def _scapy_arp_sweep(subnet_cidr: str) -> List[Tuple[str, str]]:
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet_cidr), timeout=1.6, verbose=0)
        return [(rcv.psrc, normalize_mac(rcv.hwsrc)) for _, rcv in ans]
    except Exception:
        return []


def resolve_device_identity(
    ip: str,
    mac: str,
    is_gateway: bool,
    is_self: bool,
    mdns_map: Dict[str, Tuple[str, str]],
    ssdp_map: Dict[str, Tuple[str, str]],
    dhcp_map: Dict[str, str],
) -> dict:
    """Run the 5-layer real name pipeline and record exact name_source."""
    vendor, dev_type, is_rand = lookup_mac_vendor(mac)
    os_hint = None

    if is_self:
        host = socket.gethostname().split(".")[0]
        return {
            "real_name": f"{host} (This Computer)",
            "name_source": "host",
            "vendor": vendor if vendor != "Unknown Manufacturer" else platform.system(),
            "device_type": "laptop",
            "os_hint": f"{platform.system()} {platform.release()}",
            "is_randomized_mac": is_rand,
        }

    # Layer 1: mDNS / Bonjour
    if ip in mdns_map:
        name, hint = mdns_map[ip]
        return {
            "real_name": name,
            "name_source": "mdns",
            "vendor": vendor,
            "device_type": "router" if is_gateway else infer_device_type_from_vendor_or_name(f"{name} {hint} {vendor}", dev_type),
            "os_hint": hint,
            "is_randomized_mac": is_rand,
        }

    # Layer 2: SSDP / UPnP XML <friendlyName>
    if ip in ssdp_map:
        name, hint = ssdp_map[ip]
        return {
            "real_name": name,
            "name_source": "ssdp",
            "vendor": vendor if vendor != "Unknown Manufacturer" else (hint.split()[0] if hint else vendor),
            "device_type": "router" if is_gateway else infer_device_type_from_vendor_or_name(f"{name} {hint} {vendor}", dev_type),
            "os_hint": hint,
            "is_randomized_mac": is_rand,
        }

    # Layer 3: DHCP Option 12 Hostname captured by live sniffer
    if mac.upper() in dhcp_map:
        name = dhcp_map[mac.upper()]
        return {
            "real_name": name,
            "name_source": "dhcp",
            "vendor": vendor,
            "device_type": "router" if is_gateway else infer_device_type_from_vendor_or_name(f"{name} {vendor}", dev_type),
            "os_hint": "DHCP Hostname",
            "is_randomized_mac": is_rand,
        }

    # Layer 4a: NetBIOS UDP 137
    nb = query_netbios_name(ip)
    if nb:
        return {
            "real_name": nb,
            "name_source": "netbios",
            "vendor": vendor,
            "device_type": "router" if is_gateway else infer_device_type_from_vendor_or_name(f"{nb} {vendor}", dev_type),
            "os_hint": "Windows / NetBIOS",
            "is_randomized_mac": is_rand,
        }

    # Layer 4b: Reverse DNS
    try:
        old_t = socket.getdefaulttimeout()
        socket.setdefaulttimeout(0.45)
        try:
            rdns, _, _ = socket.gethostbyaddr(ip)
            if rdns and rdns != ip:
                clean = rdns.replace(".local", "").replace(".lan", "").replace(".home", "").strip()
                return {
                    "real_name": clean,
                    "name_source": "rdns",
                    "vendor": vendor,
                    "device_type": "router" if is_gateway else infer_device_type_from_vendor_or_name(f"{clean} {vendor}", dev_type),
                    "os_hint": "Router DNS",
                    "is_randomized_mac": is_rand,
                }
        finally:
            socket.setdefaulttimeout(old_t)
    except Exception:
        pass

    # Layer 5: Honest OUI / Randomized MAC label
    if is_gateway:
        name = f"{vendor} Wi-Fi Router" if vendor != "Unknown Manufacturer" else f"Main Wi-Fi Router ({ip})"
        dev_type = "router"
    elif is_rand:
        name = f"Phone/Laptop with Private Wi-Fi MAC ({ip.split('.')[-1]})"
        os_hint = "iOS / Android / Win11 Private MAC"
    elif vendor != "Unknown Manufacturer":
        label_map = {"phone": "Phone", "laptop": "Computer", "tv": "Smart TV", "printer": "Printer", "iot": "Smart Device", "router": "Router"}
        name = f"{vendor} {label_map.get(dev_type, 'Device')} ({ip.split('.')[-1]})"
    else:
        name = f"Unidentified Device ({ip})"

    return {
        "real_name": name,
        "name_source": "oui",
        "vendor": vendor,
        "device_type": dev_type,
        "os_hint": os_hint,
        "is_randomized_mac": is_rand,
    }


def discover_lan_devices(net_info: dict, dhcp_hostnames: Optional[Dict[str, str]] = None, active_sweep: bool = True) -> List[dict]:
    """Discover all connected LAN hosts and run 5-layer real name resolution concurrently."""
    subnet_cidr = net_info["subnet_cidr"]
    local_ip = net_info["local_ip"]
    gateway_ip = net_info["gateway_ip"]
    gateway_mac = net_info["gateway_mac"]
    dhcp_map = {k.upper(): v for k, v in (dhcp_hostnames or {}).items()}

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        f_mdns = pool.submit(discover_mdns_names, 1.5)
        f_ssdp = pool.submit(discover_ssdp_names, 1.2)

        ip_to_mac: Dict[str, str] = {}
        latencies: Dict[str, int] = {}

        scapy_hits = _scapy_arp_sweep(subnet_cidr) if active_sweep else []
        for ip, mac in scapy_hits:
            ip_to_mac[ip] = mac

        if active_sweep and not scapy_hits and local_ip != "127.0.0.1":
            try:
                net = ipaddress.ip_network(subnet_cidr, strict=False)
                hosts = [str(h) for h in list(net.hosts())[:128]]
                with concurrent.futures.ThreadPoolExecutor(max_workers=48) as ping_ex:
                    futs = {ping_ex.submit(_ping_host, ip): ip for ip in hosts}
                    for fut in concurrent.futures.as_completed(futs, timeout=4.5):
                        ip = futs[fut]
                        try:
                            ms = fut.result()
                            if ms is not None:
                                latencies[ip] = ms
                        except Exception:
                            pass
            except Exception:
                pass

        for ip, mac in read_os_arp_table():
            ip_to_mac.setdefault(ip, mac)

        if gateway_ip and gateway_mac and gateway_mac != "00:00:00:00:00:00":
            ip_to_mac.setdefault(gateway_ip, gateway_mac)

        if local_ip and local_ip != "127.0.0.1" and local_ip not in ip_to_mac:
            node = uuid.getnode()
            local_mac = ":".join(f"{(node >> shift) & 0xFF:02X}" for shift in range(40, -1, -8))
            ip_to_mac[local_ip] = local_mac

        mdns_map = f_mdns.result()
        ssdp_map = f_ssdp.result()

    def _build(item):
        ip, mac = item
        is_gw = ip == gateway_ip
        is_self = ip == local_ip
        ident = resolve_device_identity(ip, mac, is_gw, is_self, mdns_map, ssdp_map, dhcp_map)
        return {
            "ip": ip,
            "mac": mac,
            "real_name": ident["real_name"],
            "name_source": ident["name_source"],
            "vendor": ident["vendor"],
            "device_type": ident["device_type"],
            "os_hint": ident["os_hint"],
            "is_gateway": is_gw,
            "is_self": is_self,
            "is_randomized_mac": ident["is_randomized_mac"],
            "latency_ms": latencies.get(ip, 1 if is_self else None),
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        devices = list(ex.map(_build, ip_to_mac.items()))

    devices.sort(key=lambda d: (not d["is_gateway"], not d["is_self"], d["ip"]))
    return devices
