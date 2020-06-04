import socket
import subprocess
from multiprocessing.dummy import Pool
import errno
import binascii

subprocess.call('cls', shell=True)


def scan_tcp(args):
    ip, port, output = args
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            output[port] += "  TCP: Открыт  "
            sock.close()
            check_tcp_protocol(ip, port, output)
        else:
            output[port] += f"  TCP: Закрыт  "
    except socket.error:
        output[port] += '  TCP: Ошибка подключения  '
    finally:
        sock.close()


def scan_udp(args):
    ip, port, output = args
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ip, port))
    sock.settimeout(1)
    closed = False
    try:
        sock.sendto(b'\x00', (ip, port))
    except socket.error as e:
        if e == errno.ECONNREFUSED:
            output[port] += f"  UDP: Закрыт  "
        else:
            output[port] += f'  UDP: Ошибка подключения {e} '
        closed = True
    if not closed:
        output[port] += "  UDP: Открыт  "
        sock.close()
        check_udp_protocol(ip, port, output)
    sock.close()


def check_dns(ip, port):
    dns_message = "AA AA 01 00 00 01 00 00 00 00 00 00 " \
                  "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"
    formatted = binascii.unhexlify(
        dns_message.replace(" ", "").replace("\n", ""))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((ip, port))
        sock.settimeout(1)
        sock.sendto(formatted, (ip, port))
        data, _ = sock.recvfrom(512)
    except socket.error:
        return False
    return is_data_dns(data)


def is_data_dns(data):
    ID = data[:2]
    return ID == binascii.unhexlify('AAAA')


def check_http(ip, port):
    request = f"HEAD / HTTP/1.1"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        result = sock.connect_ex((ip, port))
        if result != 0:
            return False
        sock.settimeout(1)
        sock.send(request.encode())
        data = sock.recv(4096)
    except socket.error:
        return False
    return data.startswith(b"HTTP/1.1")


def check_smtp(ip, port):
    request = b"HELLO"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        result = sock.connect_ex((ip, port))
        if result != 0:
            return False
        sock.settimeout(1)
        sock.send(request)
        data = sock.recv(4096)
    except socket.error:
        return False
    return data.startswith(b"220")


def check_pop3(ip, port):
    request = b"HELLO"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        result = sock.connect_ex((ip, port))
        if result != 0:
            return False
        sock.settimeout(1)
        sock.send(request)
        data = sock.recv(4096)
    except socket.error:
        return False
    return data.startswith(b"+OK")


def check_sntp(ip, port):
    request = ('\x1b' + 47 * '\0').encode('utf-8')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((ip, port))
        sock.settimeout(1)
        sock.sendto(request, (ip, port))
        data = sock.recv(512)
    except socket.error:
        return False
    return len(data) > 0


def check_tcp_protocol(ip, port, output):
    try:
        if check_http(ip, port):
            output[port] += '  Протокол: HTTP  '
        elif check_smtp(ip, port):
            output[port] += '  Протокол: SMTP  '
        elif check_pop3(ip, port):
            output[port] += '  Протокол: POP3  '
        else:
            output[port] += '  Протокол: не определен  '
    except socket.error:
        output[port] += '  Протокол: - '


def check_udp_protocol(ip, port, output):
    try:
        if check_dns(ip, port):
            output[port] += '  Протокол: ДНС  '
        elif check_sntp(ip, port):
            output[port] += '  Протокол: SNTP  '
        else:
            output[port] += '  Протокол: не определен  '
    except socket.error:
        output[port] += '  Протокол: - '


def is_udp_port_open(data):
    is_length_correct = len(data) == 128
    is_open = False
    if is_length_correct:
        btype = data[:8]
        type = int.from_bytes(btype, "big")
        if type == 3:
            bcode = data[8:16]
            code = int.from_bytes(bcode, "big")
            if code == 3:
                is_open = True
    return is_open


def multithread_scan(ip, min_port, max_port, output, target):
    pool = Pool(256)
    args = []
    for port in range(min_port, max_port):
        args.append((ip, port, output))
    pool.map(target, args)


def scan_ports(ip, min_port, max_port):
    output = {}
    for port in range(min_port, max_port):
        output[port] = ""
    print("Сканируем TCP порты")
    multithread_scan(ip, min_port, max_port, output, target=scan_tcp)
    print("Сканируем UDP порты")
    multithread_scan(ip, min_port, max_port, output, target=scan_udp)

    for i in range(min_port, max_port):
        print(f"Порт {i}: {output[i]}")


def main():
    host_ip = input("Введите IP хоста: ")
    min_port = int(input("Введите минимальный номер порта: "))
    max_port = int(input("Введите максимальный номер порта: "))
    scan_ports(host_ip, min_port, max_port + 1)


if __name__ == "__main__":
    main()
