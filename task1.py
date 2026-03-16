import ipaddress
import subprocess
import requests
import socket
import struct
import time
import sys
import os
import re

def resolve_domain_to_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "ADDRESS is invalid"


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_icmp_packet(id):
    type = 8
    code = 0
    chksum = 0
    seq = 1
    header = struct.pack("!BBHHH", type, code, chksum, id, seq)
    data = struct.pack("!d", time.time())
    chksum = checksum(header + data)
    header = struct.pack("!BBHHH", type, code, chksum, id, seq)
    return header + data

def traceroute(host, max_hops=30, timeout=2):
    try:
        dest_addr = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"{host} is invalid")
        return []

    ttl = 1
    result = []
    pid = os.getpid() & 0xFFFF  # уникальный ID пакета

    while ttl <= max_hops:
        try:
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_socket.settimeout(timeout)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        except PermissionError:
            print("pls, restart with root permission")
            return []

        packet = create_icmp_packet(pid)
        send_socket.sendto(packet, (dest_addr, 0))

        curr_addr = "*"
        try:
            data, addr = recv_socket.recvfrom(512)
            ip_header_len = (data[0] & 0x0F) * 4
            icmp_header = data[ip_header_len:ip_header_len+8]
            icmp_type, icmp_code, _, _, _ = struct.unpack("!BBHHH", icmp_header)

            if icmp_type in (0, 11):
                curr_addr = addr[0]
        except socket.timeout:
            pass
        except Exception:
            curr_addr = "*"

        result.append(curr_addr)
        ttl += 1

        send_socket.close()
        recv_socket.close()

        if curr_addr == dest_addr:
            break

    return result

def get_country_online(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = r.json()
        country = data.get("country")
        if country and country.upper() != "EU":
            return country.upper()
    except Exception:
        pass
    return None

REGIONAL_WHOIS = {
    "RIPE": "whois.ripe.net",       # Европа, Россия, Ближний Восток
    "ARIN": "whois.arin.net",       # США, Канада
    "APNIC": "whois.apnic.net",     # Азия и Тихоокеанский регион
    "LACNIC": "whois.lacnic.net",   # Латинская Америка
    "AFRINIC": "whois.afrinic.net"  # Африка
}

def get_ip_info(ip):
    info = {"netname": None, "asn": None, "country": None}

    try:
        result = subprocess.run(
            ["whois", ip],
            capture_output=True, text=True, timeout=5
        )
        text = result.stdout
    except Exception:
        return info

    m = re.search(r"refer:\s*(whois\.\S+)", text)
    whois_server = m.group(1).strip() if m else None

    # fallback по диапазонам (очень грубо)
    if not whois_server:
        first_octet = int(ip.split(".")[0])
        if 0 <= first_octet <= 126:
            whois_server = REGIONAL_WHOIS["ARIN"]
        elif 128 <= first_octet <= 191:
            whois_server = REGIONAL_WHOIS["RIPE"]
        elif 192 <= first_octet <= 223:
            whois_server = REGIONAL_WHOIS["APNIC"]
        else:
            whois_server = REGIONAL_WHOIS["RIPE"]

    # 2. Запрос к региональному серверу
    try:
        result = subprocess.run(
            ["whois", "-h", whois_server, ip],
            capture_output=True, text=True, timeout=5
        )
        text = result.stdout
    except Exception:
        return info

    # 3. Парсим нужные поля
    for line in text.splitlines():
        line = line.strip()
        lower = line.lower()

        if lower.startswith("netname:") and not info["netname"]:
            info["netname"] = line.split(":", 1)[1].strip()

        elif lower.startswith("origin:") and not info["asn"]:
            info["asn"] = line.split(":", 1)[1].strip()

        elif lower.startswith("country:"):
            country_value = line.split(":", 1)[1].strip().upper()
            if country_value != "EU" and not info["country"]:
                info["country"] = country_value

        elif lower.startswith("descr:") and not info["netname"] and not info["asn"]:
            info["netname"] = line.split(":", 1)[1].strip()

    # 4. Если после WHOIS нет конкретной страны, делаем онлайн-запрос
    if not info["country"]:
        info["country"] = get_country_online(ip)

    return info

def format_traceroute(ip_list):
    output = ""

    for i, hop in enumerate(ip_list, start=1):
        output += f"{i}. {hop}\r\n"

        if hop == "*":
            output += "\r\n"
            continue

        try:
            ip_obj = ipaddress.ip_address(hop)

            if ip_obj.is_private:
                output += "local\r\n\r\n"
            else:
                info = get_ip_info(hop)
                fields = []
                if info.get("netname"):
                    fields.append(info["netname"])
                if info.get("asn"):
                    fields.append(info["asn"])
                if info.get("country"):
                    fields.append(info["country"])
                output += ", ".join(fields) + "\r\n\r\n" if fields else "\r\n"

        except ValueError:
            output += "\r\n"

    return output


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python script.py <IP_or_domain>")
        exit(1)

    domain = resolve_domain_to_ip(sys.argv[1])
    if domain == "ADDRESS is invalid":
        print(f"{sys.argv[1]} is invalid")
        exit(0)

    ip = resolve_domain_to_ip(domain)
    hops = traceroute(ip)
    result = format_traceroute(hops)
    print(result)
