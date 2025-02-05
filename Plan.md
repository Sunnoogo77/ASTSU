## 🚀 **Plan de Travail Pédagogique**  

### **🔍 Phase 1 : Analyse de l'Architecture Générale d’ASTU**  
- **Objectif :** Comprendre la structure globale du code et le rôle de chaque composant.  
- **Ce qu'on va voir :**  
  - Architecture des modules (`astsu.py`, `service_detection.py`, `os_detection.py`).  
  - Le rôle des bibliothèques utilisées (`scapy`, `socket`, `threading`, etc.).  
  - Comment le programme est structuré avec la classe `Scanner` et la gestion des arguments en ligne de commande.  

---

### **⚙️ Phase 2 : Compréhension du Cœur du Scanner (classe `Scanner`)**  
- **Objectif :** Décomposer le fonctionnement de la classe principale.  
- **Ce qu'on va voir :**  
  - **Initialisation** de la classe : `__init__()`.  
  - **Gestion des ports :** `port_scan()`, `common_scan()`, `range_scan()`.  
  - **Gestion des résultats :** `handle_port_response()`.  
  - Différence entre les scans TCP Connect, TCP Stealth (SYN), et UDP.  

---

### **🌐 Phase 3 : Découverte de Réseau (ICMP Ping Sweep)**  
- **Objectif :** Comprendre comment ASTU détecte les hôtes actifs.  
- **Ce qu'on va voir :**  
  - Fonctionnement de `discover_net()` et `send_icmp()`.  
  - Utilisation des threads pour optimiser la vitesse de scan.  
  - Analyse des réponses ICMP et gestion des résultats.  

---

### **🖥️ Phase 4 : Détection du Système d’Exploitation (OS Scan)**  
- **Objectif :** Comprendre les techniques d’OS fingerprinting.  
- **Ce qu'on va voir :**  
  - Fonction `os_scan()` et son interaction avec `os_detection.py`.  
  - Analyse des TTL et détection des systèmes d’exploitation.  

---

### **🔎 Phase 5 : Détection de Services (Service Fingerprinting)**  
- **Objectif :** Comprendre comment ASTU identifie les services en cours d’exécution.  
- **Ce qu'on va voir :**  
  - Fonction `scan_service` dans `service_detection.py`.  
  - Interaction avec `nmap_vscan` et `service_probes`.  
  - Analyse des bannières des services pour identifier les applications.  

---

### **📊 Phase 6 : Gestion des Arguments et Interface en Ligne de Commande (CLI)**  
- **Objectif :** Comprendre la gestion des arguments pour contrôler ASTU via le terminal.  
- **Ce qu'on va voir :**  
  - Fonction `arguments()` et la bibliothèque `argparse`.  
  - Options disponibles : `-sC`, `-sA`, `-d`, `-sO`, `-p`, `-i`, etc.  
  - Exécution des différentes fonctionnalités selon les arguments fournis.  

---

### **🚀 Phase 7 : Optimisation, Personnalisation et Améliorations**  
- **Objectif :** Proposer des idées d’amélioration pour ASTU.  
- **Ce qu'on va voir :**  
  - Optimisation des performances (multithreading avancé, gestion des timeouts).  
  - Ajouter des fonctionnalités (ex : détection de vulnérabilités de base).  
  - Amélioration de l'interface utilisateur (par exemple, une interface web légère avec Flask).  

---

### ✅ **Phase 8 : Documentation et Partage de Projet**  
- **Objectif :** Préparer un post LinkedIn pour présenter le projet.  
- **Ce qu'on va voir :**  
  - Structuration d’un post technique (explications, captures d’écran, démonstrations).  
  - Conseils pour présenter ton travail de manière professionnelle.  

---

## 🚀 **Phase 1 : Analyse de l'Architecture Générale d’ASTU** (Démarrons maintenant)

### **1.1 Structure Globale du Projet**  
ASTU est structuré de manière modulaire, ce qui est parfait pour la maintenir facilement :  
```
astu/
├── astsu.py                # Script principal
├── install.py              # Script d'installation
├── requirements.txt        # Dépendances Python
├── modules/                # Modules pour la détection des services et OS
│   ├── __init__.py
│   ├── service_detection.py
│   └── os_detection.py
├── service_probes          # Probes pour le fingerprinting des services
├── .gitignore
├── README.md
└── LICENSE
```

### **1.2 Rôle de Chaque Composant**  
- **`astsu.py`** : Le cœur de l’application. C’est ici que la logique principale est implémentée.  
- **`modules/service_detection.py`** : Gère la détection des services réseau actifs (via Nmap et Scapy).  
- **`modules/os_detection.py`** : Gère la détection du système d’exploitation de la cible.  
- **`service_probes`** : Contient des signatures pour identifier les services (probablement des bannières réseau).  
- **`install.py`** : Script d’installation pour configurer ASTU sur Linux ou Windows.  
- **`requirements.txt`** : Liste des bibliothèques Python nécessaires (`scapy`, `nmap_vscan`, `colorama`, etc.).  

---

### **1.3 Bibliothèques Clés Utilisées**  
- **`scapy`** : Manipulation avancée des paquets réseau (TCP, UDP, ICMP, etc.).  
- **`socket`** : Bibliothèque standard Python pour la communication réseau.  
- **`threading`** : Pour exécuter des tâches en parallèle (utilisé dans le scan réseau pour plus de rapidité).  
- **`argparse`** : Gestion des arguments en ligne de commande.  
- **`colorama` / `rpycolors`** : Amélioration de l’affichage des résultats dans le terminal.  
- **`ipaddress`** : Gestion des plages IP pour la découverte réseau.  
- **`progress`** : Barre de progression lors des scans.  

---

### 🚀 **Phase 2 : Décryptage de la Classe `Scanner`**

La classe `Scanner` est le **cœur d’ASTU**. Elle gère toutes les opérations de scan :  
- **Scan de ports (TCP/UDP, avec et sans stealth)**  
- **Découverte d’hôtes sur le réseau**  
- **Détection du système d’exploitation**  
- **Analyse des services**  

On va la décortiquer étape par étape pour bien comprendre son fonctionnement.  

---

## 📦 **2.1 Initialisation de la Classe `Scanner`**

```python
class Scanner:
    def __init__(self, target=None, my_ip=None, protocol=None, timeout=5, interface=None):
        self.target = target
        self.my_ip = my_ip
        self.protocol = protocol
        self.timeout = timeout
        self.interface = interface
```

### **🔑 Analyse des paramètres :**  
- **`target`** : L'adresse IP ou le domaine de la cible à scanner.  
- **`my_ip`** : L’adresse IP locale de l’attaquant (utilisée pour le scan réseau).  
- **`protocol`** : Protocole à utiliser (TCP, UDP, ICMP), défini par l'argument `-p`.  
- **`timeout`** : Temps d'attente maximal pour une réponse lors des scans (par défaut 5 secondes).  
- **`interface`** : Interface réseau à utiliser pour le scan (utile si la machine a plusieurs cartes réseau).  

> **💡 Remarque :** Cette méthode est un **constructeur** qui initialise les variables d'instance accessibles dans toutes les méthodes de la classe.  

---

## 🔍 **2.2 Fonction de Scan de Ports : `port_scan()`**

C’est ici que la magie opère pour scanner des ports TCP et UDP.  

### **Code :**  
```python
def port_scan(self, stealth=None, port=80):
    protocol = self.protocol if self.protocol else "TCP"
```
- **`stealth`** : Si activé (`-st`), cela déclenche un **SYN Scan (Stealth)**.  
- **`port`** : Port à scanner (par défaut 80 si non spécifié).  

---

### **A) Mode Stealth (TCP SYN Scan)**  
```python
if stealth:
    pkt = IP(dst=self.target) / TCP(dport=port, flags="S")
    scan = sr1(pkt, timeout=self.timeout, verbose=0)
```
- **Construction du paquet :**  
  - `IP(dst=self.target)` → Définition de l’IP de destination.  
  - `TCP(dport=port, flags="S")` → Paquet TCP avec le **flag SYN** activé.  
- **Envoi du paquet :**  
  - `sr1()` → Envoie le paquet et attend une réponse (1 réponse attendue).  

#### **Analyse des réponses :**  
```python
if scan is None:
    return {port: 'Filtered'}
elif scan.haslayer(TCP):
    if scan.getlayer(TCP).flags == 0x12:  # SYN-ACK
        pkt = IP(dst=self.target) / TCP(dport=port, flags="R")
        sr(pkt, timeout=self.timeout, verbose=0)
        return {port: 'Open'}
    elif scan.getlayer(TCP).flags == 0x14:  # RST-ACK
        return {port: 'Closed'}
```
- **Pas de réponse →** Port probablement **filtré**.  
- **Réponse SYN-ACK (0x12) →** Port **ouvert**. On envoie un **RST** pour couper la connexion.  
- **Réponse RST (0x14) →** Port **fermé**.  

> **🛡️ Stealth Scan** : Le fait de ne pas compléter le handshake rend ce scan plus discret, d'où le terme "stealth".  

---

### **B) Mode TCP Connect (Scan Complet)**  
```python
if protocol == "TCP":
    pkt = IP(dst=self.target) / TCP(dport=port, flags="S")
    scan = sr1(pkt, timeout=self.timeout, verbose=0)
```
Ce bloc est similaire au mode stealth, sauf qu’il semble incomplet ici car ASTU continue d’envoyer des paquets RST. Cependant, en pratique, un **TCP Connect** utiliserait `socket` pour établir une vraie connexion.  

> **Différence clé :**  
> - **Stealth Scan :** On interrompt le handshake.  
> - **TCP Connect :** On complète le handshake (SYN → SYN-ACK → ACK).  

---

### **C) Mode UDP Scan**  
```python
elif protocol == "UDP":
    pkt = IP(dst=self.target) / UDP(dport=port)
    scan = sr1(pkt, timeout=self.timeout, verbose=0)
```
- Envoi d’un paquet UDP simple.  
- Analyse des réponses :  
  - **Pas de réponse →** Port peut être **ouvert ou filtré**.  
  - **ICMP "Port Unreachable" →** Port **fermé**.  
  - **Réponse UDP →** Port probablement **ouvert**.  

---

## 📊 **2.3 Gestion des Résultats : `handle_port_response()`**

Cette fonction classe les résultats des scans en fonction de l’état des ports.  

### **Code :**  
```python
def handle_port_response(self, ports_saved, response, port):
    open_ports = ports_saved['open']
    filtered_ports = ports_saved['filtered']
    open_or_filtered = ports_saved['open/filtered']

    if response[port] == "Closed":
        logging.warning(f"Port: {port} - Closed")
    elif response[port] == "Open":
        logging.info(f"Port: {port} - Open")
        open_ports.append(port)
    elif response[port] == "Filtered":
        logging.warning(f"Port: {port} - Filtered")
        filtered_ports.append(port)
    elif response[port] == "Open/Filtered":
        logging.info(f"Port: {port} - Open/Filtered")
        open_or_filtered.append(port)

    return (open_ports, filtered_ports, open_or_filtered)
```

### **Fonctionnement :**  
- Trie les ports en **ouvert**, **filtré**, **fermé**, ou **open/filtered**.  
- Ajoute les ports aux listes correspondantes pour un affichage ultérieur.  
- Utilise `logging` pour afficher les résultats avec des couleurs grâce à `colorama` et `rpycolors`.  

> **💡 À noter :** La gestion des logs est configurée dans le `main` pour des messages colorés dans le terminal.

---

## 🔎 **2.4 Scan des Ports Courants : `common_scan()`**

Cette fonction automatise le scan des ports les plus utilisés.  

### **Code :**  
```python
def common_scan(self, stealth=None, sv=None):
    ports = [21, 22, 80, 443, 3306, 14147, 2121, 8080, 8000]
```
- Liste des **ports courants** : FTP (21), SSH (22), HTTP (80), HTTPS (443), MySQL (3306), etc.  
- Pour chaque port, la fonction appelle `port_scan()`.  
- Résultats affichés grâce à `handle_port_response()`.  

---

## 🔢 **2.5 Scan de Plage de Ports : `range_scan()`**

Permet de scanner une **plage de ports** personnalisée.  

### **Code :**  
```python
def range_scan(self, start, end=None, stealth=None, sv=None):
    if end:
        for port in range(start, end):
            scan = self.port_scan(stealth, port=port)
```
- Si `end` est défini → scan de la plage `start` à `end`.  
- Sinon, scan d’un seul port (`start`).  
- Fonctionne aussi bien en **TCP Connect**, **Stealth**, ou **UDP** selon les arguments.  

> **💡 Astuce :** Utilise des **threads** pour accélérer le scan (à implémenter pour plus d'efficacité).

---

# 🚀 **Phase 3 : Découverte de Réseau (ICMP Ping Sweep)**

La **découverte de réseau** est une étape cruciale lors d’un pentest ou d’une évaluation de sécurité. Cela permet d’identifier les hôtes actifs sur un réseau avant de cibler des scans plus approfondis. ASTU implémente cette fonctionnalité à travers deux fonctions clés :  
- **`discover_net()`** : Gère la découverte globale des hôtes.  
- **`send_icmp()`** : Envoie des paquets ICMP pour vérifier la présence des hôtes.  

---

## 🌐 **3.1 Fonction `discover_net()`**

### 📄 **Code :**  
```python
def discover_net(self, ip_range=24):
    protocol = self.protocol
    base_ip = self.my_ip

    if not protocol:
        protocol = "ICMP"
    else:
        if protocol != "ICMP":
            logging.warning(f"Warning: {protocol} is not supported by discover_net function! Changed to ICMP")

    if protocol == "ICMP":
        logging.info("Starting - Discover Hosts Scan")

        base_ip = base_ip.split('.')
        base_ip = f"{str(base_ip[0])}.{str(base_ip[1])}.{str(base_ip[2])}.0/{str(ip_range)}"

        hosts = list(ipaddress.ip_network(base_ip))
        bar = ChargingBar("Scanning...", max=len(hosts))

        sys.stdout = None
        bar.start()

        threads = [None] * len(hosts)
        results = [None] * len(hosts)

        for i in range(len(threads)):
            threads[i] = Thread(target=self.send_icmp, args=(hosts[i], results, i))
            threads[i].start()

        for i in range(len(threads)):
            threads[i].join()
            bar.next()

        bar.finish()
        sys.stdout = sys.__stdout__

        hosts_found = [i for i in results if i is not None]

        if not hosts_found:
            logging.warning('Not found any host')
        else:
            logging.info(f'{len(hosts_found)} hosts found')
            for host in hosts_found:
                logging.info(f'Host found: {host}')

        return True
    else:
        logging.critical("Invalid protocol for this scan")
        return False
```

---

### 🧩 **Analyse de la Logique**

1. **Définition du Protocole (ICMP par défaut) :**  
   ```python
   if not protocol:
       protocol = "ICMP"
   ```
   - Si aucun protocole n’est défini, ASTU utilise ICMP par défaut.  
   - Si un autre protocole est spécifié (TCP/UDP), il affiche un avertissement et repasse à ICMP.  

2. **Génération de la Plage d’Adresses IP :**  
   ```python
   base_ip = base_ip.split('.')
   base_ip = f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.0/{ip_range}"
   hosts = list(ipaddress.ip_network(base_ip))
   ```
   - ASTU convertit l’adresse IP locale en une **plage de type `/24`** (par défaut), ce qui correspond à 256 adresses IP.  
   - Utilisation du module `ipaddress` pour générer toutes les adresses de la plage.  

   **Exemple :**  
   - IP locale = `192.168.1.34` → ASTU va scanner de `192.168.1.0` à `192.168.1.255`.  

3. **Barre de Progression :**  
   ```python
   bar = ChargingBar("Scanning...", max=len(hosts))
   bar.start()
   ```
   - Utilisation de la bibliothèque `progress` pour afficher une barre de progression pendant le scan.  

4. **Scan Multi-threadé :**  
   ```python
   threads = [None] * len(hosts)
   results = [None] * len(hosts)

   for i in range(len(threads)):
       threads[i] = Thread(target=self.send_icmp, args=(hosts[i], results, i))
       threads[i].start()
   ```
   - Chaque adresse IP est scannée dans un **thread séparé**.  
   - Cela accélère le processus en envoyant plusieurs paquets ICMP en parallèle.  
   - Le résultat de chaque thread est stocké dans la liste `results`.  

5. **Collecte des Résultats :**  
   ```python
   hosts_found = [i for i in results if i is not None]
   ```
   - ASTU filtre les adresses IP qui ont répondu au ping.  
   - Si des hôtes sont trouvés, ils sont affichés. Sinon, un message d’erreur est retourné.  

---

### ✅ **Résultat attendu :**  
Lors de l’exécution de la commande :  
```bash
astsu -d
```  
Tu obtiendras :  
```
[*] Starting - Discover Hosts Scan
Scanning... |████████████████████████████████████████| 256/256
[*] 3 hosts found
[*] Host found: 192.168.1.1
[*] Host found: 192.168.1.12
[*] Host found: 192.168.1.34
```

---

## 📡 **3.2 Fonction `send_icmp()`**

### 📄 **Code :**  
```python
def send_icmp(self, target, result, index):
    target = str(target)
    host_found = []
    pkg = IP(dst=target) / ICMP()
    answers, unanswered = sr(pkg, timeout=3, retry=2, verbose=0, iface=self.interface if self.interface else None)
    answers.summary(lambda r: host_found.append(target))

    if host_found:
        result[index] = host_found[0]
```

---

### 🚀 **Analyse de la Logique**

1. **Création du Paquet ICMP :**  
   ```python
   pkg = IP(dst=target) / ICMP()
   ```
   - Construction d’un paquet ICMP de type **Echo Request** (comme la commande `ping`).  
   - `IP(dst=target)` définit l’adresse de destination.  
   - `ICMP()` ajoute l’en-tête ICMP par défaut.  

2. **Envoi du Paquet et Attente de Réponse :**  
   ```python
   answers, unanswered = sr(pkg, timeout=3, retry=2, verbose=0)
   ```
   - Envoie du paquet ICMP avec `sr()` (send/receive).  
   - Timeout de 3 secondes par tentative.  
   - **2 tentatives** (`retry=2`) pour les hôtes silencieux.  

3. **Traitement des Réponses :**  
   ```python
   answers.summary(lambda r: host_found.append(target))
   ```
   - Si une réponse ICMP est reçue, l’adresse IP de la cible est ajoutée à `host_found`.  

4. **Stockage des Résultats :**  
   ```python
   if host_found:
       result[index] = host_found[0]
   ```
   - Le résultat est stocké dans la liste `results` à l’index correspondant.  
   - Cela permet de conserver l’ordre des hôtes scannés.  

---

### 💡 **Optimisation via le Multithreading**

Le scan d’un réseau peut être très lent si chaque IP est scannée séquentiellement. ASTU utilise des **threads** pour :  
- Envoyer plusieurs requêtes ICMP en parallèle.  
- Réduire le temps total de scan, surtout sur des plages IP étendues (/24, /16, etc.).  

**Avantage :**  
- **Rapidité** : Un scan de 256 IP peut être fait en quelques secondes.  
- **Efficacité** : Moins d’attente par IP grâce à la parallélisation.  

---

## ⚡ **3.3 Exemple de Scan Réseau avec ASTU**

### **Commande :**  
```bash
astsu -d -i eth0
```
- `-d` : Découverte des hôtes.  
- `-i eth0` : Spécifie l’interface réseau à utiliser (utile sur des machines multi-cartes réseau).  

### **Résultat attendu :**  
```
[*] Starting - Discover Hosts Scan
Scanning... |████████████████████████████████████████| 256/256
[*] 5 hosts found
[*] Host found: 192.168.1.1
[*] Host found: 192.168.1.12
[*] Host found: 192.168.1.15
[*] Host found: 192.168.1.34
[*] Host found: 192.168.1.101
```

---

## 🔎 **3.4 Limites de la Découverte ICMP**

Bien que rapide et simple, la méthode ICMP a des limites :  
- **Pare-feux** : De nombreux pare-feux bloquent les paquets ICMP (anti-ping).  
- **Équipements réseau configurés pour ignorer ICMP** : Certains serveurs n'y répondent pas.  
- **Solutions :**  
  - **Scan ARP** sur les réseaux locaux (très efficace pour contourner le blocage ICMP).  
  - **TCP Ping Sweep** : Envoyer des paquets SYN sur des ports courants (80, 443) pour détecter des hôtes actifs même si ICMP est bloqué.  

---

# 🚀 **Phase 4 : Détection du Système d’Exploitation (OS Scan)**

La **détection du système d’exploitation (OS fingerprinting)** est une étape clé dans la phase de reconnaissance d'un test de pénétration. Connaître le système d’exploitation d'une cible permet d'adapter les attaques, d'identifier des vulnérabilités spécifiques et de mieux cibler les services exposés.  

Dans ASTU, cette fonctionnalité est implémentée principalement à travers :  
- **`os_scan()`** dans `astsu.py`  
- **`scan()`** dans `os_detection.py`  

On va détailler ces fonctions et expliquer les concepts d’OS fingerprinting.  

---

## 🖥️ **4.1 Fonction `os_scan()` (dans `astsu.py`)**

### 📄 **Code :**  
```python
def os_scan(self):
    target_os = os_detection.scan(self.target)
    
    if target_os:
        print("")
        logging.info(f"Target OS: {target_os}")
    else:
        logging.warning("[[red]-[/red]] Error when scanning OS")
```

### 🔍 **Analyse de la Logique**

1. **Appel de la Fonction de Détection :**  
   ```python
   target_os = os_detection.scan(self.target)
   ```
   - La détection réelle de l'OS est effectuée par la fonction `scan()` du module `os_detection.py`.  
   - ASTU lui passe l'adresse IP de la cible.  

2. **Affichage des Résultats :**  
   - Si un système d’exploitation est identifié, il est affiché avec un message d’information.  
   - Sinon, un message d’erreur est généré.  

**Commande pour exécuter la détection de l’OS :**  
```bash
astsu -sO 192.168.1.1
```

---

## 🧬 **4.2 Fonction `scan()` (dans `os_detection.py`)**

### 📄 **Code :**  
```python
from scapy.all import *

def scan(target, interface=None):
    try:
        os_ttl = {
            'Linux/Unix 2.2-2.4 >': 255,
            'Linux/Unix 2.0.x kernel': 64,
            'Windows 98': 32,
            'Windows': 128
        }
        pkg = IP(dst=target, ttl=128) / ICMP()

        if interface:
            ans, uns = sr(pkg, retry=5, timeout=3, inter=1, verbose=0, iface=interface)
        else:
            ans, uns = sr(pkg, retry=5, timeout=3, inter=1, verbose=0)

        try:
            target_ttl = ans[0][1].ttl
        except:
            print("[-] Host did not respond")
            return False

        for ttl in os_ttl:
            if target_ttl == os_ttl[ttl]:
                return ttl
    except:
        return False
```

---

### 🔍 **Analyse de la Logique**

1. **Base de Données des TTL par Système d’Exploitation :**  
   ```python
   os_ttl = {
       'Linux/Unix 2.2-2.4 >': 255,
       'Linux/Unix 2.0.x kernel': 64,
       'Windows 98': 32,
       'Windows': 128
   }
   ```
   - Chaque système d’exploitation utilise un **TTL (Time To Live)** par défaut pour les paquets IP.  
   - ASTU utilise cette différence pour tenter d’identifier l'OS de la cible.  

   **Exemples courants de TTL par défaut :**  
   - **Windows :** 128  
   - **Linux/Unix :** 64  
   - **Cisco/Routeurs :** 255  

---

2. **Création et Envoi du Paquet ICMP :**  
   ```python
   pkg = IP(dst=target, ttl=128) / ICMP()
   ans, uns = sr(pkg, retry=5, timeout=3, inter=1, verbose=0)
   ```
   - ASTU crée un paquet ICMP (comme la commande `ping`).  
   - Le TTL est fixé à 128, mais cela n'a pas d’impact sur la détection car ASTU lit le TTL de la **réponse**.  
   - `sr()` envoie le paquet et attend une réponse.  

---

3. **Extraction du TTL de la Réponse :**  
   ```python
   target_ttl = ans[0][1].ttl
   ```
   - ASTU récupère le TTL de la réponse ICMP retournée par la cible.  

   **Important :**  
   - Le TTL est **diminué à chaque saut de routeur**.  
   - Si le TTL initial est 128 (Windows), et qu’il passe par 3 routeurs, la réponse aura un TTL de 125.  

---

4. **Identification de l'OS en Fonction du TTL :**  
   ```python
   for ttl in os_ttl:
       if target_ttl == os_ttl[ttl]:
           return ttl
   ```
   - ASTU compare le TTL reçu avec sa base de données `os_ttl`.  
   - Si une correspondance est trouvée, l’OS est identifié.  

---

### 🧪 **Exemple de Résultat**

```bash
astsu -sO 192.168.1.1
```
**Sortie attendue :**  
```
[*] Target OS: Windows
```
Ou si la cible est un serveur Linux :  
```
[*] Target OS: Linux/Unix 2.0.x kernel
```

---

## 🎯 **4.3 Limites de la Détection Basée sur le TTL**

La détection basée sur le TTL est **simple**, mais elle a des limites :  

### ❌ **Limitations :**  
1. **Réseaux Complexes :**  
   - Le TTL diminue à chaque saut de routeur.  
   - Sur des réseaux multi-sauts, le TTL final peut être trompeur.  

2. **Systèmes Configurés Manuellement :**  
   - Certains administrateurs modifient le TTL par défaut pour des raisons de sécurité.  
   - Cela fausse la détection.  

3. **Pare-feux et IDS :**  
   - Certains dispositifs de sécurité modifient le TTL des paquets ICMP.  
   - D'autres bloquent carrément les réponses ICMP.  

---

## 🚀 **4.4 Amélioration de la Détection d’OS (Approche Avancée)**

Pour améliorer la détection d’OS, ASTU pourrait :  

1. **Combiner plusieurs techniques :**  
   - **Analyse des bannières de services** (via des scans TCP sur des ports comme 22, 80, 443).  
   - **TCP Fingerprinting** : Analyse des réponses TCP SYN/ACK (comme le fait Nmap).  
   - **Analyse des paramètres TCP/IP** : Options TCP, fenêtre de taille, etc.  

2. **Utiliser des Paquets Spécifiques :**  
   - Envoi de paquets TCP malformés pour observer des comportements spécifiques aux OS.  
   - Analyse des champs comme DF (Don’t Fragment), TOS (Type of Service), etc.  

3. **Ajout d’une Base de Données Plus Complète :**  
   - Intégration de signatures d’OS plus détaillées.  
   - Utilisation de `service_probes` pour enrichir la détection.  

---

# 🔍 **Phase 5 : Détection de Services (Service Fingerprinting)**

La **détection de services** (ou **service fingerprinting**) consiste à identifier les services en cours d'exécution sur des ports ouverts d’une machine cible. Cela inclut :  
- Le type de service (HTTP, FTP, SSH, etc.)  
- La version exacte du service (par ex. Apache 2.4.41)  
- Parfois même le système d’exploitation sous-jacent  

Dans ASTU, cette fonctionnalité repose sur :  
- **`scan_service()`** dans `service_detection.py`  
- L’utilisation de **`nmap_vscan`** et du fichier **`service_probes`**  

---

## 🗂️ **5.1 Fonction `scan_service()` (dans `service_detection.py`)**

### 📄 **Code :**  
```python
from nmap_vscan import vscan
import sys, platform

def scan_service(target, port):
    return True  # Ce retour arrête la fonction prématurément (à corriger !)

    if platform.system() == 'Linux':
        nmap = vscan.ServiceScan('/usr/share/astsu/service_probes')
    elif platform.system() == 'Windows':
        nmap = vscan.ServiceScan('C:\\Projetos\\Tools\\Network Tool\\service_probes')

    try:
        result = nmap.scan(str(target), int(port), 'tcp')
    except Exception as e:
        return e

    service_name = str(result['match']['versioninfo']['cpename'])
    service_name = service_name.replace('[', '').replace(']', '').replace("'", "", 2)

    if not service_name:
        service_name = 'Not found any service'

    return service_name
```

---

### 🚩 **Problème immédiat à corriger :**  
```python
return True
```
Cette ligne annule toute la logique de la fonction. Il faudra la supprimer pour que la détection de services fonctionne correctement.  

---

### 🔍 **Analyse de la Logique**

1. **Détection de l’OS Hôte :**  
   ```python
   if platform.system() == 'Linux':
       nmap = vscan.ServiceScan('/usr/share/astsu/service_probes')
   elif platform.system() == 'Windows':
       nmap = vscan.ServiceScan('C:\\Projetos\\Tools\\Network Tool\\service_probes')
   ```
   - ASTU détecte si l’outil tourne sur **Linux** ou **Windows**.  
   - Il charge le fichier `service_probes`, qui contient des signatures pour identifier les services réseau (similaire à `nmap-service-probes` de Nmap).  

2. **Scan du Port Cible :**  
   ```python
   result = nmap.scan(str(target), int(port), 'tcp')
   ```
   - Appel à la méthode `scan()` de `nmap_vscan.ServiceScan`.  
   - Cette méthode envoie des requêtes personnalisées (probes) sur le port spécifié pour identifier le service actif.  

3. **Extraction des Informations du Service :**  
   ```python
   service_name = str(result['match']['versioninfo']['cpename'])
   service_name = service_name.replace('[', '').replace(']', '').replace("'", "", 2)
   ```
   - ASTU extrait le nom du service et sa version à partir des résultats retournés par `nmap_vscan`.  
   - Nettoyage des caractères inutiles pour un affichage propre.  

4. **Retour du Résultat :**  
   ```python
   if not service_name:
       service_name = 'Not found any service'
   return service_name
   ```
   - Si aucun service n'est détecté, un message par défaut est affiché.  

---

## ⚙️ **5.2 Qu’est-ce que `nmap_vscan` ?**

Bien qu’on n’ait pas accès au code source de `nmap_vscan`, il est probable que ce module :  
- **Imite le comportement de Nmap** pour le service fingerprinting.  
- Utilise des **probes réseau** stockés dans le fichier `service_probes` pour interroger les services sur les ports ouverts.  
- Analyse les **bannières de réponse** des services pour identifier leur type et leur version.  

---

## 📜 **5.3 Rôle du Fichier `service_probes`**

Le fichier `service_probes` fonctionne probablement de la même manière que le fichier `nmap-service-probes` utilisé par Nmap. Il contient des modèles de requêtes (probes) et des signatures pour :  
- **Envoyer des requêtes spécifiques à des services courants** (HTTP, FTP, SMTP, etc.)  
- **Analyser les réponses** pour en déduire le service et sa version  

### 📊 **Exemple d’un Probe Typique :**  
```plaintext
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
match http m|^HTTP/1\.[01] \d{3} .*\r\nServer: ([^\r\n]+)|
```
- **Probe** : Envoie une requête HTTP GET sur un port ouvert.  
- **Match** : Analyse la réponse pour identifier le serveur (Apache, Nginx, etc.).  

---

## 🧪 **5.4 Exemple de Détection de Service avec ASTU**

### **Commande :**  
```bash
astsu -sC -sV 192.168.1.1
```
- `-sC` : Scan des ports courants.  
- `-sV` : Activation de la détection des services.  

### **Sortie attendue :**  
```
[*] Port: 80 - Open
[*] Service detected: Apache 2.4.41
[*] Port: 22 - Open
[*] Service detected: OpenSSH 7.9
```

---

## 🚀 **5.5 Comment Améliorer la Détection de Services ?**

### 🔍 **Idées d’amélioration :**  
1. **Suppression de la ligne `return True`** pour activer la fonctionnalité.  
2. **Optimisation des probes dans `service_probes`** pour couvrir plus de services.  
3. **Ajout de nouvelles techniques de fingerprinting :**  
   - **Analyse des bannières TCP** sans envoyer de requêtes spécifiques (passif).  
   - **Fingerprinting SSL/TLS** pour les services sécurisés (HTTPS, SMTPS).  
   - **Détection des services masqués** via des techniques d’évasion (ex : services sur des ports non standards).  

4. **Optimisation des performances :**  
   - Implémentation de **threads** pour scanner plusieurs services en parallèle.  
   - Gestion des **timeouts adaptatifs** selon les services scannés.  

---

