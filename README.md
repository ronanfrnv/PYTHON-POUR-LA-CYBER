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

