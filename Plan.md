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

## 🚩 **Bilan de la Phase 2**

### 🔑 **Ce qu'on a compris :**  
- **`port_scan()`** gère la logique de scan pour TCP (Connect/SYN) et UDP.  
- **`handle_port_response()`** trie les résultats des scans.  
- **`common_scan()`** et **`range_scan()`** permettent de cibler des ports précis ou des plages entières.  

### ✅ **Prochaine Étape : Phase 3 - Découverte de Réseau (ICMP Ping Sweep)**  
On va analyser :  
1. **`discover_net()`** : Comment ASTU détecte les hôtes actifs sur un réseau.  
2. **`send_icmp()`** : Le rôle des paquets ICMP et la gestion des réponses.  
3. **Utilisation des threads pour des scans rapides.**  

Prêt pour la suite ? 🚀