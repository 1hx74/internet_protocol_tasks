#!/usr/bin/env python3
"""
Fake SNTP server — отвечает клиентам фиктивным временем с опциональным сдвигом.
"""

import socket
import struct
import time
import argparse
from concurrent.futures import ThreadPoolExecutor


NTP_DELTA = 2208988800  # разница между эпохами NTP (1900) и Unix (1970)

def system_to_ntp_time(timestamp):
    return timestamp + NTP_DELTA


# ─── Формирование NTP-пакета ───

def build_response(request, delay, recv_time):
    """
    Строит NTP-ответ на основе полученного запроса.
    Возвращает байты пакета или None, если запрос слишком короткий.
    """
    if len(request) < 48:
        return None

    # --- Заголовок: разбор запроса и сборка первого байта ответа ---
    first_byte = request[0]
    version    = (first_byte >> 3) & 0x07

    LI   = 0   # leap indicator: нет предупреждения
    VN   = version
    MODE = 4   # режим: сервер
    first_response_byte = (LI << 6) | (VN << 3) | MODE

    # --- Поля фиксированного заголовка ---
    stratum    = 2
    poll       = request[2]
    precision  = -20
    root_delay = 0
    root_dispersion = 0
    ref_id     = b'LOCL'

    # --- Временны́е метки ---
    now      = recv_time + delay
    ntp_time = system_to_ntp_time(now)
    seconds  = int(ntp_time)
    fraction = int((ntp_time - seconds) * (2 ** 32))

    originate_timestamp = request[40:48]  # Transmit timestamp клиента
    reference_timestamp = struct.pack("!II", seconds, fraction)
    receive_timestamp   = struct.pack("!II", seconds, fraction)
    transmit_timestamp  = struct.pack("!II", seconds, fraction)

    # --- Сборка пакета ---
    packet  = struct.pack(
        "!BBBbII4s",
        first_response_byte,
        stratum,
        poll,
        precision,
        root_delay,
        root_dispersion,
        ref_id,
    )
    packet += reference_timestamp
    packet += originate_timestamp
    packet += receive_timestamp
    packet += transmit_timestamp

    return packet


# ─── Обработка одного клиента ───

def handle_client(data, addr, sock, delay, recv_time):
    """Формирует NTP-ответ и отправляет его клиенту."""
    response = build_response(data, delay, recv_time)
    if response:
        sock.sendto(response, addr)
        print(f"Response sent to {addr[0]}:{addr[1]}")


def main():
    # --- Аргументы командной строки ---
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--delay", type=int, default=0,
                        help="Сдвиг времени в секундах (по умолчанию 0)")
    parser.add_argument("-p", "--port",  type=int, default=123,
                        help="UDP-порт сервера (по умолчанию 123)")
    args = parser.parse_args()

    print(f"Starting fake SNTP server on port {args.port}, delay={args.delay}s")

    # --- Создание и привязка сокета ---
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))

    # --- Основной цикл приёма: каждый клиент — отдельный поток ---
    with ThreadPoolExecutor(max_workers=50) as pool:
        while True:
            data, addr = sock.recvfrom(1024)
            recv_time = time.time()
            pool.submit(handle_client, data, addr, sock, args.delay, recv_time)


if __name__ == "__main__":
    main()


    # check on mac - "ntpdate -q 127.0.0.1"
