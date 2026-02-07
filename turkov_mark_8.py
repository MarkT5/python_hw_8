import argparse
import socket
import random
import time
import gzip
from urllib.parse import urlparse
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap, Raw
from bs4 import BeautifulSoup


def resolve_hostname(hostname):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения доменного имени '{hostname}': {e}")
        return None


def parse_url(url_arg):
    """Парсит URL и извлекает hostname, path и scheme."""
    if not url_arg.startswith('http://') and not url_arg.startswith('https://'):
        url_arg = 'http://' + url_arg

    try:
        parsed = urlparse(url_arg)
        hostname = parsed.hostname
        path = parsed.path if parsed.path else '/'
        scheme = parsed.scheme or 'http'
        return hostname, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None


def send_http_request(hostname, path, custom_request=None):
    """Отправляет HTTP-запрос через Scapy."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    port = 80
    client_sport = random.randint(1025, 65500)

    # Формируем HTTP-запрос
    if custom_request:
        http_request_str = custom_request
    else:
        http_request_str = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'

    # Устанавливаем TCP-соединение
    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
    syn_ack = sr1(syn, timeout=5, verbose=False)

    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
        print(f"Не удалось установить соединение с {hostname}")
        return None

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

    send(http_request, verbose=False)

    return dest_ip, port, client_sport


def capture_traffic(hostname, timeout=5, output_file=None):
    """Перехватывает HTTP-трафик для указанного хоста."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None
    print(hostname, timeout, output_file)
    filter_str = f"host {dest_ip}"
    print(f"Начало перехвата трафика для {hostname} ({dest_ip})...")
    packets = sniff(iface="\\Device\\NPF_{5D8CE303-8BDE-411D-9E56-91FD77DA047E}", filter=filter_str,
                    timeout=timeout)

    if output_file and packets:
        wrpcap(output_file, packets)
        print(f"Трафик сохранен в {output_file}")

    return packets


class TCPStream():
    def __init__(self, stream_id, expected_seq):
        self.stream_id = stream_id
        self.data = b''
        self.expected_seq = expected_seq
        self.is_http = False
        self.headers = None
        self.exp_data_len = 0


def analyze_packets(packets):
    """Базовый анализ перехваченных пакетов."""
    if not packets:
        print("Нет пакетов для анализа")
        return

    http_data = []

    # Сборка пакетов
    streams = {}
    start = packets[0].time
    for pkt in packets:
        print()
        print(pkt.time - start, pkt.summary())
        if not pkt.haslayer(TCP):
            continue
        layer = None
        if pkt.haslayer(HTTP):
            layer = HTTP
        if layer:
            print("has layer, reading raw")
            has_data = pkt[Raw].load if pkt.haslayer(Raw) else None
        else:
            print("reading tcp")
            has_data = pkt[TCP].payload

        # Идентификатор потока
        src = (pkt[IP].src, pkt[TCP].sport)
        dst = (pkt[IP].dst, pkt[TCP].dport)
        stream_id = (src, dst)
        print("now analysing:", stream_id)

        # Инициализируем поток если нужно
        if stream_id not in streams:
            print("this is a new stream")
            streams[stream_id] = TCPStream(stream_id, pkt[TCP].seq)

        # Проверяем sequence number
        current_seq = pkt[TCP].seq
        expected_seq_ = streams[stream_id].expected_seq
        print("current_seq", current_seq, "|  expected_seq", expected_seq_)

        # Если это следующий ожидаемый сегмент
        if current_seq == expected_seq_:
            print("add packet")
            if has_data:
                print("adding data")
                data = has_data
                streams[stream_id].data += data
            streams[stream_id].expected_seq = current_seq + len(pkt[TCP].payload)
            streams[stream_id].is_http += bool(layer)
            if pkt.haslayer(HTTPRequest): streams[stream_id].headers = pkt[HTTPRequest]
            if pkt.haslayer(HTTPResponse): streams[stream_id].headers = pkt[HTTPResponse]
        if hasattr(pkt[layer], "Content_Length") and pkt[layer].Content_Length:
            cont_len = int(pkt[layer].Content_Length.decode("UTF-8"))
            print("new expected content length is:", cont_len)
            streams[stream_id].exp_data_len = cont_len
        elif streams[stream_id].exp_data_len:
            cont_len = streams[stream_id].exp_data_len
            print("for this stream expected content length is:", cont_len)
        else:
            cont_len = None

        if not cont_len:
            if layer:
                if not streams[stream_id].headers:
                    if pkt.haslayer(HTTPRequest): streams[stream_id].headers = pkt[HTTPRequest]
                    if pkt.haslayer(HTTPResponse): streams[stream_id].headers = pkt[HTTPResponse]
                print("singular packet")
                http_data.append((streams[stream_id].headers, streams[stream_id].data))
                del streams[stream_id]
        else:
            print("compare length:", cont_len, len(streams[stream_id].data))
            if cont_len <= len(streams[stream_id].data):
                print("PACKET FINISHED")
                http_data.append((streams[stream_id].headers, streams[stream_id].data))
                del streams[stream_id]

        # Проверка, завершен ли поток (FIN флаг)
        if pkt[TCP].flags & 0x01:  # FIN
            http_data.append((streams[stream_id].headers, streams[stream_id].data))

    # Декомпрессия сообщений
    parsed_packets = []
    for i, data in enumerate(http_data):
        headers = data[0]
        try:
            if hasattr(headers, "Content_Encoding"):
                if b"gzip" in headers.Content_Encoding:
                    parsed_packets.append((headers, gzip.decompress(data[1])))
            else:
                parsed_packets.append((headers, data[1]))
        except gzip.BadGzipFile as e:
            parsed_packets.append((headers, data[1]))

    print(f"Найдено HTTP-сообщений: {len(parsed_packets)}")
    # for h, p in parsed_packets:
    #     h.show()
    #     print(BeautifulSoup(p, 'html.parser').prettify())
    return parsed_packets


def analyze_saved_traffic(pcap_file, output):
    """Анализирует сохраненный трафик из .pcap файла."""
    print(f"Анализ трафика из файла: {pcap_file}")
    packets = rdpcap(pcap_file)
    res = analyze_packets(packets)
    if output:
        with open(output, "w") as out_file:
            for rs in res:
                out_file.write(rs[0].summary()+"\n")
                out_file.write(rs[0]._show_or_dump(dump=True))
                out_file.write(BeautifulSoup(rs[1], 'html.parser').prettify()+"\n")


def main():
    parser = argparse.ArgumentParser(
        description='Анализ XSS-уязвимостей с использованием Scapy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Примеры использования:
            # Отправка HTTP-запроса
            python scapy_xss_analyzer.py --send google-gruyere.appspot.com/XXXXX
            
            # Перехват трафика
            python scapy_xss_analyzer.py --capture google-gruyere.appspot.com --timeout 60 --output traffic.pcap
            
            # Анализ сохраненного трафика
            python scapy_xss_analyzer.py --analyze traffic.pcap
        """
    )

    parser.add_argument(
        '--send',
        metavar='URL',
        help='Отправить HTTP-запрос на указанный URL'
    )

    parser.add_argument(
        '--capture',
        metavar='HOSTNAME',
        help='Перехватить трафик для указанного хоста'
    )

    parser.add_argument(
        '--analyze',
        metavar='PCAP_FILE',
        help='Проанализировать сохраненный трафик из .pcap файла'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Таймаут для перехвата трафика в секундах (по умолчанию: 30)'
    )

    parser.add_argument(
        '--output',
        metavar='FILE',
        help='Имя файла для сохранения перехваченного трафика'
    )

    parser.add_argument(
        '--request',
        metavar='HTTP_REQUEST',
        help='Кастомный HTTP-запрос (для этапа 3)'
    )

    args = parser.parse_args()

    # Проверка аргументов
    if not any([args.send, args.capture, args.analyze]):
        parser.print_help()
        return

    # Отправка HTTP-запроса
    if args.send:
        hostname, path, scheme = parse_url(args.send)
        if not hostname:
            print("Ошибка: не удалось распарсить URL")
            return

        print(f"Отправка HTTP-запроса на {hostname}{path}")
        result = send_http_request(hostname, path, args.request)
        if result:
            print("HTTP-запрос отправлен")
        else:
            print("Ошибка при отправке HTTP-запроса")

    # Перехват трафика
    if args.capture:
        packets = capture_traffic(args.capture, args.timeout, args.output)
        print("Captured total:", len(packets))
        if packets:
            analyze_packets(packets)

    # Анализ сохраненного трафика
    if args.analyze:
        analyze_saved_traffic(args.analyze, args.output)


if __name__ == '__main__':
    main()
