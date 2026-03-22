# 1.1.1.1 # http
# 8.8.8.8 # dns
# 94.100.180.74 # pop3
# 217.69.139.90 # imap
# 154.18.236.98 # smtp
# 127.0.0.1 # ntp (но сначала его надо включить из файла 6.py)

import socket
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor

results = {}
results_lock = threading.Lock()


def check_dns(ip, port):
    payload = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    try:
        sock.sendto(payload, (ip, port))
        sock.recvfrom(1024)
        return True
    except:
        return False
    finally:
        sock.close()


def check_ntp(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    try:
        sock.sendto(b"\x1b" + 47 * b"\x00", (ip, port))
        data, _ = sock.recvfrom(1024)
        return len(data) >= 48
    except:
        return False
    finally:
        sock.close()


def check_tcp_banner(ip, port, keyword):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(4)
    try:
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors="ignore")
        return keyword in banner
    except:
        return False
    finally:
        sock.close()


def check_http(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(4)
    try:
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        return sock.recv(1024).decode(errors="ignore").startswith("HTTP/")
    except:
        return False
    finally:
        sock.close()


def is_tcp_open(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((ip, port))
        return True
    except:
        return False
    finally:
        sock.close()


def is_udp_open(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    try:
        sock.sendto(b"ping", (ip, port))
        sock.recvfrom(1024)
        return True
    except:
        return False
    finally:
        sock.close()


UDP_PROTOCOLS = [
    ("DNS", check_dns),
    ("NTP", check_ntp),
]

TCP_PROTOCOLS = [
    ("SMTP", lambda ip, port: check_tcp_banner(ip, port, "220")),
    ("POP3", lambda ip, port: check_tcp_banner(ip, port, "+OK")),
    ("IMAP", lambda ip, port: check_tcp_banner(ip, port, "* OK")),
    ("HTTP", check_http),
]


def scan_port(ip, port, do_tcp, do_udp):
    found = []

    if do_tcp and is_tcp_open(ip, port):
        proto = next((name for name, check in TCP_PROTOCOLS if check(ip, port)), None)
        found.append(f"TCP {port} {proto}" if proto else f"TCP {port}")

    if do_udp:
        udp_proto = next(
            (name for name, check in UDP_PROTOCOLS if check(ip, port)), None
        )
        if udp_proto:
            found.append(f"UDP {port} {udp_proto}")
        elif is_udp_open(ip, port):
            found.append(f"UDP {port}")

    if found:
        with results_lock:
            results[port] = found


def main():
    parser = argparse.ArgumentParser(description="Port scanner")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("-t", action="store_true", help="Scan TCP")
    parser.add_argument("-u", action="store_true", help="Scan UDP")
    parser.add_argument(
        "-p",
        "--ports",
        nargs=2,
        type=int,
        metavar=("N1", "N2"),
        default=[1, 1024],
        help="Port range (default: 1-1024)",
    )
    args = parser.parse_args()

    # если ни -t ни -u не указано — сканируем оба
    do_tcp = args.t or not (args.t or args.u)
    do_udp = args.u or not (args.t or args.u)

    port_range = range(args.ports[0], args.ports[1] + 1)
    print(
        f"Scanning {args.ip} ports {args.ports[0]}-{args.ports[1]} "
        f"{'TCP' if do_tcp else ''} {'UDP' if do_udp else ''}\n"
    )

    try:
        with ThreadPoolExecutor(max_workers=500) as executor:
            executor.map(lambda p: scan_port(args.ip, p, do_tcp, do_udp), port_range)
    except KeyboardInterrupt:
        print("Stop")

    for port in sorted(results):
        for line in results[port]:
            print(line)


if __name__ == "__main__":
    main()
