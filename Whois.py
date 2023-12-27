import socket
import requests
from ipwhois import IPWhois
import scapy.all as scapy
from scapy.layers.inet import IP, ARP, Ether, TCP
from scapy.sendrecv import sr1

def get_basic_info(ip_address):
    try:
        host_name = socket.gethostbyaddr(ip_address)[0]
        print(f"Hostname: {host_name}")

        ip = socket.gethostbyname(host_name)
        print(f"Indirizzo IP: {ip}")

    except socket.herror as e:
        print(f"Errore durante la ricerca dell'hostname: {e}")
    except socket.error as e:
        print(f"Errore durante la connessione al socket: {e}")

def get_location_info(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()

        if data["status"] == "fail":
            print(f"Impossibile ottenere informazioni sulla posizione per {ip_address}")
            return

        print("Informazioni sulla posizione:")
        print(f"Paese: {data['country']}")
        print(f"Regione: {data['regionName']}")
        print(f"Città: {data['city']}")
        print(f"Latitudine: {data['lat']}")
        print(f"Longitudine: {data['lon']}")
        print(f"ISP: {data['isp']}")

    except requests.exceptions.RequestException as e:
        print(f"Errore durante la richiesta delle informazioni sulla posizione: {e}")

def get_whois_info(ip_address):
    try:
        ipwhois_obj = IPWhois(ip_address)
        result = ipwhois_obj.lookup_rdap()

        print("Informazioni WHOIS:")
        for key, value in result.items():
            print(f"{key}: {value}")

    except Exception as e:
        print(f"Errore durante la ricerca delle informazioni WHOIS: {e}")

def get_ip_range(ip_address, subnet_mask):
    ip = ip_address.split('.')
    base_ip = '.'.join(ip[:3]) + '.'
    return base_ip + '1/24'

def scan(ip_range):
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices_list = []
    for element in answered_list:
        device_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices_list.append(device_dict)
    return devices_list

def scan_ports(ip_address, ports, timeout=1):
    open_ports = []
    for port in ports:
        packet = IP(dst=ip_address)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
    return open_ports

if __name__ == "__main__":
    target_ip = input("Inserisci l'indirizzo IP da cui iniziare la scansione: ")
    target_subnet = input("Inserisci la subnet mask (es. 255.255.255.0): ")

    ip_range = get_ip_range(target_ip, target_subnet)
    devices = scan(ip_range)

    print("Dispositivi sulla rete:")
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

    target_device_ip = input("Inserisci l'IP del dispositivo per la scansione delle porte: ")

    ports_to_scan = range(1, 1025)  # Puoi modificare l'intervallo delle porte se necessario
    open_ports = scan_ports(target_device_ip, ports_to_scan)

    print("\nOpzioni:")
    print("1. Informazioni di base sull'IP")
    print("2. Informazioni sulla posizione dell'IP")
    print("3. Informazioni WHOIS sull'IP")
    print("4. Tutte le informazioni")
    print("5. Scansione delle porte")

    choice = input("Scelta: ")

    if choice == "1":
        get_basic_info(target_ip)
    elif choice == "2":
        get_location_info(target_ip)
    elif choice == "3":
        get_whois_info(target_ip)
    elif choice == "4":
        get_basic_info(target_ip)
        get_location_info(target_ip)
        get_whois_info(target_ip)
    elif choice == "5":
        if open_ports:
            print("\nPorte aperte:")
            for port in open_ports:
                print(f"Porta {port} aperta")
        else:
            print("\nNessuna porta aperta trovata.")
    else:
        print("Scelta non valida.")
