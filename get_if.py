from scapy.all import get_if_list, get_if_addr, conf
import platform


def show_if():
    print("Список сетевых интерфейсов:")
    print("=" * 60)

    interfaces = get_if_list()

    for i, iface in enumerate(interfaces, 1):
        try:
            ip = get_if_addr(iface) or "нет IP"
            print(f"{i}. {iface} ({ip})")
        except:
            print(f"{i}. {iface} (ошибка получения данных)")

    print(f"\nВсего интерфейсов: {len(interfaces)}")

    # Показываем интерфейс по умолчанию
    print(f"Интерфейс по умолчанию: {conf.iface}")

    return interfaces

print(show_if())