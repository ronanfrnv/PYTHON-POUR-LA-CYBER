from scapy.all import sr1, IP, TCP, conf

def tcp_scan(hote, port):
    tcp_packet = IP(dst=hote)/TCP(dport=port, flags='S')
    response = sr1(tcp_packet, timeout=1, verbose=0)
    
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        print(f"Le port {port} sur l'hôte {hote} est ouvert.")
    else:
        print(f"Le port {port} sur l'hôte {hote} est fermé.")

# Hôte cible
hote = "10.102.252.25"

# Ports à scanner
ports = [80, 22]  # Vous pouvez ajouter d'autres ports ici

# Réaliser le scan pour chaque port
for port in ports:
    tcp_scan(hote, port)
