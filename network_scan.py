import scapy.all as scapy
from optparse import OptionParser

def get_arguments():
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target", help="IP/Range to scan (e.g., 192.168.1.0/24)")
    (options, _) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP/Range, use --help for info")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients = []
    for response in answered_list:
        client_info = {"ip": response[1].psrc, "mac": response[1].hwsrc}
        clients.append(client_info)
    return clients

def print_result(results):
    print("\nDiscovered devices:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in results:
        print(f"{client['ip']}\t{client['mac']}")

if __name__ == "__main__":
    options = get_arguments()
    scan_results = scan(options.target)
    print_result(scan_results)