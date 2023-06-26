# PYTHON-POUR-LA-CYBER

Script python coté client
```
import socket
import sys

# Définition des constantes
BUFFER_SIZE = 1024
MESSAGE_TO_SERVER = 'LE MESSAGE EST : Coucou les RT !'

try:
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Création du socket client
except socket.error:
    sys.exit()

tcp_socket.connect((TCP_IP, TCP_PORT))  # Connexion au serveur

try:
    tcp_socket.send(MESSAGE_TO_SERVER.encode('utf8'))  # Envoi du message au serveur
except socket.error:
    sys.exit()

print("Message envoyé au serveur avec succès")

data = tcp_socket.recv(BUFFER_SIZE)  # Réception de la réponse du serveur

tcp_socket.close()  # Fermeture du socket client

print("Réponse du serveur :", data)


```

Script coté serveur

```
import socket
import sys

# Définition des constantes
TCP_IP_srv = '10.102.252.25'
TCP_PORT = 2004
BUFFER_SIZE = 1024

try:
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Création du socket serveur
except socket.error:
    print('Une erreur est apparue pendant la création du socket')
    sys.exit()

tcp_socket.bind((TCP_IP_srv, TCP_PORT))  # Liaison du socket au serveur

tcp_socket.listen(3)  # Mise en écoute du socket

print('En écoute ...')

connexion, adresse = tcp_socket.accept()  # Attente d'une connexion client

print('Connecté avec :', adresse)

data = connexion.recv(BUFFER_SIZE)  # Réception du message du client

print("Message reçu du client :", data)

reponse_server = 'Merci pour la connexion'
connexion.sendall(reponse_server.encode('utf8'))  # Envoi d'une réponse au client

connexion.close()  # Fermeture de la connexion

```
Pour maintenir la connexion ajout de la ligne `While :`
Script coté serveur

```
import socket
import sys

# Définition des constantes
TCP_IP_srv = '10.102.252.25'
TCP_PORT = 2004
BUFFER_SIZE = 1024

try:
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Création du socket serveur
except socket.error:
    print('Une erreur est apparue pendant la création du socket')
    sys.exit()

tcp_socket.bind((TCP_IP_srv, TCP_PORT))  # Liaison du socket au serveur

tcp_socket.listen(3)  # Mise en écoute du socket

print('En écoute ...')

connexion, adresse = tcp_socket.accept()  # Attente d'une connexion client

print('Connecté avec :', adresse)
while True:
  data = connexion.recv(BUFFER_SIZE)  # Réception du message du client

  print("Message reçu du client :", data)

  reponse_server = 'Merci pour la connexion'
  connexion.sendall(reponse_server.encode('utf8'))  # Envoi d'une réponse au client

connexion.close()  # Fermeture de la connexion

```
### Sniffer « basique
```

import socket
import struct
import binascii

try:
       raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
except socket.error as e:
       sys.exit();
while True:
       packet = raw_socket.recvfrom(2048)
       ethernet_header = packet[0][0:14]
       eth_header = struct.unpack("!6s6s2s", ethernet_header)
       print('Destination :', binascii.hexlify(eth_header[0]))
       print('Source :', binascii.hexlify(eth_header[1]))
       print('Type :', binascii.hexlify(eth_header[2]))
       ip_header = packet[0][14:34]
       ip_hdr = struct.unpack("!12s4s4s", ip_header)
       print('Source IP :', socket.inet_ntoa(ip_hdr[1]))
       print('Destination IP :', socket.inet_ntoa(ip_hdr[2]))

```
### Utilisation de Scapy
```
sudo  scapy
```
```
sniff(filter="icmp", iface="eth0", count=4)
```

Voici ce que fait cette commande en détail :

    "sniff" est une fonction de Scapy utilisée pour capturer des paquets réseau.
    "filter="icmp"" spécifie un filtre pour la capture des paquets ICMP. ICMP (Internet Control Message Protocol) est un protocole utilisé pour les messages de contrôle et les messages d'erreur dans les réseaux IP.
    "iface="eth0"" spécifie l'interface réseau à utiliser pour la capture des paquets. Dans cet exemple, "eth0" est l'interface réseau spécifiée.
    "count=4" indique le nombre de paquets à capturer. Dans cet exemple, la commande capturera 4 paquets ICMP.

En résumé, cette commande utilise Scapy pour capturer 4 paquets ICMP sur l'interface réseau "eth0".

### Python Scan de port

Avec le script présent dans le répertoire celui-ci liste les ports ouvert


### Script pour faire l'équivalent d'un NSLOOKUP

```
import socket

ip_address = "10.108.239.251"
try:
    host_name = socket.gethostbyaddr(ip_address)[0]
    print("Le nom de domaine associé à l'adresse IP", ip_address, "est:", host_name)
except socket.herror:
    print("Impossible de résoudre le nom de domaine pour l'adresse IP", ip_address)

```

### Get_ips_par_recherche_dns

```
import socket

def get_ips_par_recherche_dns(cible, port=443):
    """
    Cette fonction utilise la fonction gethostbyname_ex du module socket pour obtenir
    les adresses IP associées à un nom de domaine spécifié.

    Arguments :
    - cible : le nom de domaine à rechercher
    - port (optionnel) : le port par défaut est 443

    Retourne :
    - Une liste contenant les adresses IP associées au nom de domaine, ou une liste vide si aucune adresse n'est trouvée.
    """
    try:
        ips = socket.gethostbyname_ex(cible)[2]  # Obtient les adresses IP associées au nom de domaine
        return ips
    except socket.gaierror:
        return []  # Retourne une liste vide si une erreur se produit lors de la recherche DNS

# Exemple d'utilisation
cible = "iut-acy.local"
ips = get_ips_par_recherche_dns(cible)
print(ips)


```

### Script pour lister chaque type de DNS
```
import dns.resolver

# Importe le module dns.resolver pour résoudre les enregistrements DNS

def resolve_dns_records(target):
    # Définit les types d'enregistrements DNS à rechercher
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
    # Initialise un dictionnaire vide pour stocker les résultats
    results = {}

    # Boucle sur chaque type d'enregistrement DNS
    for record_type in record_types:
        try:
            # Tente de résoudre l'enregistrement DNS pour le type donné
            answers = dns.resolver.resolve(target, record_type)
            # Stocke les réponses dans le dictionnaire des résultats
            results[record_type] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            # Si aucune réponse n'est trouvée, stocke une liste vide dans les résultats
            results[record_type] = []

    # Retourne le dictionnaire des résultats
    return results

# Définit la cible pour laquelle résoudre les enregistrements DNS
target = "iut-acy.local"

# Appelle la fonction pour résoudre les enregistrements DNS pour la cible donnée
results = resolve_dns_records(target)

# Parcourt les résultats et affiche les enregistrements non vides
for record_type, records in results.items():
    if len(records) > 0:
        print(f"{record_type} enregistrements pour {target}:")
        for record in records:
            print(record)
        print()


```
### Analyse des fichiers Wireshark
```
from scapy.all import *
paquets_captures = rdpcap('capture_meta_1.pcap')
for paquet in paquets_captures:
	print(paquet.summary())
   #  ou
	print(paquet.show())

```
Pour afficher
- L’adresse IP Source
- L’adresse IP Destination
- Le flag TCP
- Le port Source

```
### Affichage des détails d’un segment TCP
```
# Importation de toutes les fonctionnalités de la bibliothèque Scapy
from scapy.all import *

# Définition d'une fonction pour analyser un fichier pcap
def analyze_pcap(pcap_file):
    # Lecture du fichier pcap et stockage des paquets dans une variable
    packets = rdpcap(pcap_file)

    # Parcours de chaque paquet dans la capture
    for packet in packets:
        # Vérification si le paquet contient une couche IP
        if IP in packet:
            # Extraction de l'adresse IP source et destination
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            # Vérification si le paquet contient une couche TCP
            if TCP in packet:
                # Extraction des indicateurs TCP (flags) et du port source
                tcp_flags = packet[TCP].flags
                tcp_sport = packet[TCP].sport

                # Affichage des informations extraites
                print("Adresse IP Source:", ip_src)
                print("Adresse IP Destination:", ip_dst)
                print("Flag TCP:", tcp_flags)
                print("Port Source:", tcp_sport)
                print()

# Chemin vers le fichier pcap à analyser
pcap_file = "capture_filtrage_1.pcap"

# Appel de la fonction d'analyse du fichier pcap
analyze_pcap(pcap_file)

```
# Analyse de trame
### Importation de la bibliothèque pyshark, qui fournit une interface Python pour l'outil d'analyse réseau Wireshark.
import pyshark

### Création d'un objet FileCapture en spécifiant le chemin vers le fichier pcap ("trame_echo_1.pcap").
capture = pyshark.FileCapture("trame_echo_1.pcap")

### Création d'un dictionnaire vide pour stocker les informations des paquets TCP.
dico_layer_tcp = {}

### Initialisation d'une variable compteur.
n = 0

### Parcours de chaque paquet dans la capture.
for pqt in capture:
    // Stockage des informations de la couche TCP du paquet dans le dictionnaire en utilisant le compteur comme clé.
    dico_layer_tcp[n] = pqt.tcp
    // Incrémentation du compteur.
    n += 1

# Affichage des informations de la couche TCP du paquet à l'index 2 du dictionnaire.
print(dico_layer_tcp[2])

```
