## 🚀 **Plan de Travail Pédagogique**  

**[Notion](https://www.notion.so/Suivi-du-Projet-ASTSU-195a6f7c605880549a55cfde7e9db21c?showMoveTo=true&saveParent=true)**

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

### ----------------------------------------------  

---

## 🚀 **Phase 1 : Analyse de l'Architecture Générale d’ASTU** (Démarrons maintenant)

### **1.1 Structure Globale du Projet**  
ASTU est structuré de manière modulaire, ce qui est parfait pour la maintenir facilement :  
```
astu/       
├── .venv/  
├── modules/                
│   ├── __init__.py
│   ├── service_detection.py
│   ├─── os_detection.py
│   └── __pycache__/                
│       ├── __init__.cpython-312.pyc
│       ├── os_detection.cpython-312.pyc
│       └── service_detection.cpython-312.pyc
│
├── astsu.py                # Script principal
├── install.py              # Script d'installation
├── requirements.txt
├── service_probes         
├── .gitignore
├── README.md
└── LICENSE
```

### **1.2 Rôle de Chaque Composant**  
- **`astsu.py`** : Le cœur de l’application. C’est ici que la logique principale est implémentée.  
- **`modules/service_detection.py`** : Gère la détection des services réseau actifs (via Scapy).  
- **`modules/os_detection.py`** : Gère la détection du système d’exploitation de la cible. 
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
    def __init__(self, target=None, my_ip=None, protocol=None, timeout=5, interface=None, port=None):
        self.target = args.Target if args.Target else target
        self.my_ip = my_ip
        self.protocol = protocol
        self.timeout = args.timeout if args.timeout else 5
        self.interface = args.interface if args.interface else None
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
    pkt = scapy.IP(dst=self.target) / scapy.TCP(dport=port, flags="S")
    scan = scapy.sr1(pkt, timeout=self.timeout, verbose=0)
```
- **Construction du paquet :**  
  - `scapy.IP(dst=self.target)` → Définition de l’IP de destination.  
  - `scapy.TCP(dport=port, flags="S")` → Paquet TCP avec le **flag SYN** activé.  
- **Envoi du paquet :**  
  - `scapy.sr1()` → Envoie le paquet et attend une réponse (1 réponse attendue).  

#### **Analyse des réponses :**  
```python
if scan is None:
    return {port: 'Filtered'}

elif scan.haslayer(scapy.TCP):
    if scan.getlayer(scapy.TCP).flags == 0x12: # 0x12 SYN+ACk
        pkt = scapy.IP(dst=self.target) / scapy.TCP(dport = port, flags="R")
        send_rst = scapy.sr(pkt, timeout=self.timeout, verbose=0)
        return {port: 'Open'}
    
    elif scan.getlayer(scapy.TCP).flags == 0x14:
        return {port: 'Closed'}
    
elif scan.getlayer(scapy.ICMP):
    if scan.getlayer(scapy.ICMP).type == 3 and int(scan.getlayer(scapy.ICMP).code in [1,2,3,9,10,13]):
        return {port: 'Filtered'}
```
- **Pas de réponse →** Port probablement **filtré**.  
- **Réponse SYN-ACK (0x12) →** Port **ouvert**. On envoie un **RST** pour couper la connexion.  
- **Réponse RST (0x14) →** Port **fermé**.  

> **🛡️ Stealth Scan** : Le fait de ne pas compléter le handshake rend ce scan plus discret, d'où le terme "stealth".  

---

### **B) Mode TCP Connect (Scan Complet)**  
```python
if protocol == "TCP":
    pkt = scapy.IP(dst=self.target)/scapy.TCP(dport=port, flags="S")
    scan = scapy.sr1(pkt, timeout=self.timeout, verbose=0)
```
Ce bloc est similaire au mode stealth, sauf qu’il semble incomplet ici car ASTU continue d’envoyer des paquets RST. Cependant, en pratique, un **TCP Connect** utiliserait `socket` pour établir une vraie connexion.  

> **Différence clé :**  
> - **Stealth Scan :** On interrompt le handshake.  
> - **TCP Connect :** On complète le handshake (SYN → SYN-ACK → ACK).  

---

### **C) Mode UDP Scan**  
```python
elif protocol == "UDP":
    pkt = scapy.IP(dst=self.target)/scapy.UDP(dport=port)
    scan = scapy.sr1(pkt, timeout=self.timeout, verbose=0)
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
    open_port = ports_saved['open']
    filtered_ports = ports_saved['filtered']
    open_or_filtered = ports_saved['open/filtered']
    closed_ports = ports_saved['closed']
    
    if response[port] == 'Closed':
        print(f"[CLOSED]      ------> Port {port}")
        closed_ports.append(port)
    elif response[port] == 'Open':
        print(f"[OPEN]        ------> Port {port}")
        open_port.append(port)
    elif response[port] == 'Filtered':
        print(f"[FILTERED]     -----> Port {port}")
        filtered_ports.append(port)
    elif response[port] == 'Open/Filtered':
        print(f"[OPEN/FILTERED]  --> Port {port}")
        open_or_filtered.append(port)
    else:
        pass
    
    return open_port, filtered_ports, open_or_filtered, closed_ports
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
    protocol = self.protocol if self.protocol else "TCP"
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
    ....
    ....
    
    if end:
        ports = range(start, end + 1)
    else:
        ports = [start]

    for port in ports:
        scan = self.port_scan(port=port, stealth=stealth)
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
def discover_net(self, ip_range=24, max_threads=50):
        protocol = self.protocol if self.protocol else "ICMP"

        if protocol != "ICMP":
            print(f"\n\n❌ [WARNING] {protocol} n'est pas supporté ! Utilisation forcée d'ICMP.\n")
            print("❌ [ERROR] Protocole invalide pour ce scan.\n\n")
            return False

        try:
            print(f"\n\n\t🔍 Démarrage - Découverte des hôtes sur le réseau [ Interface : {args.interface} ]\n\n")
            
            base_ip_parts = self.my_ip.split('.')
            if len(base_ip_parts) != 4:
                logging.critical("[ERROR] Adresse IP locale invalide !")
                return False

            base_ip = f"{base_ip_parts[0]}.{base_ip_parts[1]}.{base_ip_parts[2]}.0/{ip_range}"
            network = ipaddress.ip_network(base_ip, strict=False)
            hosts = list(network.hosts())
            

        except ValueError as e:
            print(f"[ERROR] Erreur avec l'adresse IP fournie : {e}\n")
            return False

        # Utilisation de ThreadPoolExecutor pour le multitâche
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            results_queue = Queue()
            bar = ChargingBar("[INFO] Scan en cours...", max=len(hosts))
            
            
            futures = [executor.submit(self.send_icmp, host, results_queue) for host in hosts]
            bar.start()
            
            for _ in concurrent.futures.as_completed(futures):
                bar.next()
            bar.finish()
            print("\n")

            # Récupération des résultats
            hosts_found = []
            while not results_queue.empty():
                result = results_queue.get()
                if result:
                    hosts_found.append(result)
        
        

        # Affichage des résultats triés
        if not hosts_found:
            print("\n⚠️ Aucun hôte actif trouvé.")
            print("🔹 Vérifiez que les machines sont allumées.")
            print("🔹 Vérifiez si le pare-feu bloque les requêtes ICMP.")
            return []
        
        hosts_found.sort()  # Trier les IP trouvées dans l'ordre
        print(f"\n\t-----{len(hosts_found)} Hôtes Actifs Trouvés-----\n")
        
        hosts_found_tuple = []
        for host in hosts_found:
            try:
                hostname, _, _ = socket.gethostbyaddr(host)
            except socket.herror:
                hostname = "N/A - Hostname not found"
                
            print(f"\t{host}  ➜   {hostname}")
            hosts_found_tuple.append((host, hostname))
        print("\n")
        
        return hosts_found_tuple
```
---

### 🧩 **Analyse de la Logique**

1. **Définition du Protocole (ICMP par défaut) :**

    ```python
    protocol = self.protocol if self.protocol else "ICMP"

    if protocol != "ICMP":
        print(f"\n\n❌ [WARNING] {protocol} n'est pas supporté ! Utilisation forcée d'ICMP.\n")
        print("❌ [ERROR] Protocole invalide pour ce scan.\n\n")
        return False
    ```

    - Si aucun protocole n'est défini, ASTU utilise ICMP par défaut.
    - Si un autre protocole est spécifié (TCP/UDP), ASTU affiche un avertissement et utilise ICMP.  Cette version du code ne permet plus l'utilisation d'un autre protocole que ICMP pour la découverte d'hôtes.

2. **Génération de la Plage d’Adresses IP :**

    ```python
    try:
        print(f"\n\n\t Démarrage - Découverte des hôtes sur le réseau [ Interface : {args.interface} ]\n\n")

        base_ip_parts = self.my_ip.split('.')
        if len(base_ip_parts) != 4:
            logging.critical("[ERROR] Adresse IP locale invalide !")
            return False

        base_ip = f"{base_ip_parts[0]}.{base_ip_parts[1]}.{base_ip_parts[2]}.0/{ip_range}"
        network = ipaddress.ip_network(base_ip, strict=False) #strict=False permet d'éviter une erreur si l'ip est malformé
        hosts = list(network.hosts())

    except ValueError as e:
        print(f"[ERROR] Erreur avec l'adresse IP fournie : {e}\n")
        return False
    ```

    - ASTU récupère l'adresse IP locale (`self.my_ip`) et la convertit en une plage d'adresses IP au format CIDR (par exemple, `/24` par défaut).
    - Utilisation du module `ipaddress` pour générer toutes les adresses IP de la plage.
    - L'argument `strict=False` permet d'éviter une erreur si l'adresse IP fournie est malformée.
    - Un bloc `try...except` permet de gérer les erreurs potentielles lors de la création du réseau IP.

    **Exemple :**
    - IP locale = `192.168.1.34` et `ip_range = 24` → ASTU va scanner de `192.168.1.1` à `192.168.1.254` (les adresses d'hôte dans le réseau 192.168.1.0/24).

3. **Scan Multi-threadé :**

    ```python
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        results_queue = Queue()
        bar = ChargingBar("[INFO] Scan en cours...", max=len(hosts))

        futures = [executor.submit(self.send_icmp, host, results_queue) for host in hosts]
        bar.start()

        for _ in concurrent.futures.as_completed(futures):
            bar.next()
        bar.finish()
        print("\n")
    ```

    - Utilisation de `concurrent.futures.ThreadPoolExecutor` pour gérer les threads. C'est une manière plus moderne et plus simple que de gérer les threads manuellement.
    - Chaque adresse IP est scannée dans un thread séparé, ce qui accélère le processus.
    - Les résultats sont stockés dans une `queue.Queue` pour éviter les problèmes de concurrence.
    - Une barre de progression est affichée pendant le scan.  La barre de progression est mise à jour au fur et à mesure que les threads se terminent.  `concurrent.futures.as_completed(futures)` permet de récupérer les résultats des threads dans l'ordre de leur complétion.

4. **Collecte et Affichage des Résultats :**

    ```python
    hosts_found = []
    while not results_queue.empty():
        result = results_queue.get()
        if result:
            hosts_found.append(result)

    if not hosts_found:
        print("\n⚠️ Aucun hôte actif trouvé.")
        print(" Vérifiez que les machines sont allumées.")
        print(" Vérifiez si le pare-feu bloque les requêtes ICMP.")
        return []

    hosts_found.sort()  # Trier les IP trouvées dans l'ordre
    print(f"\n\t-----{len(hosts_found)} Hôtes Actifs Trouvés-----\n")

    hosts_found_tuple = []
    for host in hosts_found:
        try:
            hostname, _, _ = socket.gethostbyaddr(host)
        except socket.herror:
            hostname = "N/A - Hostname not found"

        print(f"\t{host}  ➜   {hostname}")
        hosts_found_tuple.append((host, hostname))
    print("\n")

    return hosts_found_tuple
    ```

    - Les résultats sont récupérés de la `results_queue`.
    - Les adresses IP trouvées sont triées.
    - Les noms d'hôte associés à chaque adresse IP sont recherchés à l'aide de `socket.gethostbyaddr()`.
    - Les adresses IP et leurs noms d'hôte sont affichés.
    - La fonction retourne une liste de tuples contenant les adresses IP et les noms d'hôte.

---

### ✅ **Résultat attendu :**

Lors de l’exécution de la commande :

```bash
astsu -d
```

Tu obtiendras :

```
        🔍 Démarrage - Découverte des hôtes sur le réseau [ Interface : eth0 ]


[INFO] Scan en cours... ████████████████████████████████ 100%



        -----3 Hôtes Actifs Trouvés-----

    192.168.1.1   ➜   MonOrdinateur
    192.168.1.12  ➜   Serveur_Web
    192.168.1.34  ➜   N/A - Hostname not found
```
---

## 🚀 **3.2 Fonction `send_icmp()`**  

### 📄 **Code :**  

```python
def send_icmp(self, target, results_queue):
    target = str(target)

    pkg = scapy.IP(dst=target) / scapy.ICMP()

    answers, _ = scapy.sr(pkg, timeout=3, retry=2, verbose=0, iface=self.interface if self.interface else None)

    if answers:
        results_queue.put(target)
```

---

### 🔍 **Analyse du Code**  

#### **1️ Création du Paquet ICMP**  
```python
pkg = IP(dst=target) / ICMP()
```
- Crée un **paquet ICMP de type Echo Request** (comme `ping`).  
- `IP(dst=target)` définit l’adresse de destination.  
- `ICMP()` ajoute l’en-tête ICMP (type **Echo Request** par défaut).  

#### **2️ Envoi du Paquet & Attente de Réponse**  
```python
answers, _ = sr(pkg, timeout=3, retry=2, verbose=0, iface=self.interface if self.interface else None)
```
- Envoie le paquet avec `sr()` (**send and receive**).  
- **Timeout de 3 secondes** pour la réponse.  
- **2 tentatives (`retry=2`)** pour maximiser la détection des hôtes silencieux.  
- Utilisation de **`iface=self.interface`** pour spécifier une interface réseau (optionnelle).  

#### **3️ Traitement des Réponses**  
```python
if answers:
    results_queue.put(target)
```
- Si une **réponse ICMP est reçue**, l’IP du **cible est stockée** dans `results_queue`.  
- Cela permet de collecter **uniquement les adresses des hôtes actifs** sur le réseau.  

---

## ⚡ **3.3 Optimisation avec le Multithreading**  

Un **scan séquentiel** d’un réseau est **très lent** 🚶. ASTU utilise **les threads** pour :  
**Envoyer plusieurs requêtes ICMP en parallèle**.  
**Réduire drastiquement le temps total de scan** (idéal pour `/24`, `/16`, etc.).  

| **Méthode** | **Temps approximatif pour 256 IP** |
|------------|--------------------------------|
| **Scan Séquentiel** | **~5 minutes** (selon le réseau) |
| **Scan Multithreadé** | **~5-10 secondes** |

### **Avantages du Multithreading**  
**Rapidité** : Scan **256 IP en quelques secondes**.  
**Moins d’attente** : Chaque thread envoie une requête **sans attendre les autres**.  

---

## 🔎 **3.4 Exemple de Scan Réseau avec ASTU**  

### **Commande :**  
```bash
astsu -d -i eth0
```
- `-d` : Active la découverte des hôtes.  
- `-i eth0` : Spécifie l’interface réseau à utiliser.  

### **Résultat attendu :**  
```

        🔍 Démarrage - Découverte des hôtes sur le réseau [ Interface : eth0 ]


[INFO] Scan en cours... ████████████████████████████████ 100%



        -----3 Hôtes Actifs Trouvés-----

    192.168.1.1   ➜   MonOrdinateur
    192.168.1.12  ➜   Serveur_Web
    192.168.1.34  ➜   N/A - Hostname not found
```

---

## ⚠️ **3.5 Limites de la Découverte ICMP**  

Bien que rapide et efficace, l’**ICMP Scan** a ses **limites** :  

**Pare-feux** : Beaucoup de pare-feux bloquent les requêtes **ICMP Echo Request** (`ping`).  
**Équipements réseau configurés pour ignorer ICMP**.  
**Ne fonctionne pas toujours sur les machines Windows modernes (firewall activé)**.  

### **Solutions Alternatives**  
🔹 **Scan ARP** : Très efficace pour détecter les hôtes **sur un réseau local**.  
🔹 **TCP Ping Sweep** : Envoi de **paquets SYN** sur des ports ouverts (`80`, `443`, etc.).  
🔹 **Scan UDP** : Moins fiable, mais peut identifier certains équipements.  

---

## 🔥 **3.6 Améliorations Futures**  
**Ajouter une détection automatique des interfaces réseau**.  
**Supporter d'autres méthodes de scan (ARP, TCP, UDP)**.  
**Exporter les résultats en JSON/CSV** pour une meilleure analyse.  

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
    target_os_str = ''
    if target_os:
        if target_os == 'Linux' or target_os == 'Windows':
            print(f"\n\tSystème d'exploitation détecté : {target_os}\n")
            target_os_str = "OS detected : " + str(target_os)
        else:
            print(f"\n\t---- : {target_os}\n")
            target_os_str = "----- : " + str(target_os)
    else:
        print("\n\t[[red]-[/red]] [ERROR] Impossible de détecter le système d'exploitation\n")
    return target_os_str
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
            'Linux':[64],
            'Windows':[128, 255],
            'Unix/BSD':[255]
        }
        
        icmp_pkt = scapy.IP(dst=target, ttl=128) / scapy.ICMP()
        
        if interface:
            ans, uns = scapy.sr(icmp_pkt, retry=5, timeout=3, inter=1, verbose=0, iface=interface)
        else:
            ans, uns = scapy.sr(icmp_pkt, retry=5, timeout=3, inter=1, verbose=0)
        
        if len(ans) == 0:
            print(" ICMP bloqué. Possible firewall détecté !")
            return "Firewall détecté"
        
        try:
            target_ttl = ans[0][1].ttl
        except:
            print("[-] Hôte injoignable via ICMP")
            return "OS Inconnu"
        
        #Analyse du TTL
        detected_os = "Os Inconnu"
        for os_name, ttl_values in os_ttl.items():
            if target_ttl in ttl_values:
                detected_os = os_name
                break 
        
        #Fingerprinting TCP (envoie d'un paquet SYN sur un prt ouvert)
        tcp_pkt = scapy.IP(dst=target) / scapy.TCP(dport=80, flags='S')
        tcp_resp  = scapy.sr1(tcp_pkt, timeout=3, verbose=0)
        
        if tcp_resp and tcp_resp.haslayer(scapy.TCP):
            flags = tcp_resp.getlayer(scapy.TCP).sprintf('%flags%')
            if flags == 0x12: #SYNC-ACK reçu
                detected_os += " - (TCP stack analysé)"
            elif flags == 0x14: #RST-ACK reçu
                detected_os += " - (TCP stack detecté)"
        
        tcp_ack_pkt = scapy.IP(dst=target) / scapy.TCP(dport=80, flags='A')  # "A" = ACK
        ack_resp = scapy.sr1(tcp_ack_pkt, timeout=3, verbose=0)

        if ack_resp is None:
            print("⚠️  Aucun retour au paquet ACK. Un firewall filtre peut-être les connexions.")
            return detected_os + " - Firewall détecté"
            
        return detected_os
    
    except Exception as e:
        print("[-] Erreur lors de la détection de l'OS: ", e)
        return "OS Inconnu"
```

---

### 🔍 **Analyse de la Logique**  

#### **1️ Base de Données des TTL par Système d’Exploitation**  
```python
os_ttl = {
    'Linux': [64],
    'Windows': [128, 255],
    'Unix/BSD': [255]
}
```
- Chaque **OS utilise un TTL par défaut** pour les paquets IP envoyés.  
- ASTU exploite cette caractéristique pour **identifier la cible**.  

#### **Exemples courants de TTL :**  
| **Système**      | **TTL par défaut** |
|------------------|------------------|
| **Windows**      | 128, 255         |
| **Linux**        | 64               |
| **Unix/BSD**     | 255              |
| **Cisco/Routeurs** | 255            |

---

#### **2️ Création et Envoi du Paquet ICMP**  
```python
icmp_pkt = scapy.IP(dst=target, ttl=128) / scapy.ICMP()
ans, uns = scapy.sr(icmp_pkt, retry=5, timeout=3, inter=1, verbose=0)
```
- **Construction du paquet ICMP** (`ping`).  
- `sr()` **envoie le paquet et attend une réponse**.  
- **5 tentatives** (`retry=5`) pour maximiser la détection.  
- Timeout de **3 secondes** par tentative.  

---

#### **3️ Extraction du TTL de la Réponse**  
```python
target_ttl = ans[0][1].ttl
```
- **Récupère le TTL de la réponse ICMP** retournée par la cible.  
- Si aucune réponse n’est reçue :  
  ```python
  print(" ICMP bloqué. Possible firewall détecté !")
  return "Firewall détecté"
  ```
  **Possibilité** : L’hôte bloque les `ping`, un pare-feu est actif.  

---

#### **4️ Identification de l'OS en Fonction du TTL**  
```python
for os_name, ttl_values in os_ttl.items():
    if target_ttl in ttl_values:
        detected_os = os_name
        break
```
- **Compare le TTL reçu** avec la base de données `os_ttl`.  
- **Si une correspondance est trouvée, l’OS est détecté**.  

---

#### **5️ Fingerprinting TCP : Détection via SYN-ACK**  
```python
tcp_pkt = scapy.IP(dst=target) / scapy.TCP(dport=80, flags='S')
tcp_resp  = scapy.sr1(tcp_pkt, timeout=3, verbose=0)
```
- **Envoie un paquet TCP SYN** sur le port 80.  
- **Attente de réponse** :  
  - `SYN-ACK` reçu → L’OS accepte la connexion.  
  - `RST-ACK` reçu → L’OS refuse mais indique son comportement.  
- Permet **d'affiner la détection OS**.  

---

#### **6️ Vérification de Filtrage Firewall via ACK**  
```python
tcp_ack_pkt = scapy.IP(dst=target) / scapy.TCP(dport=80, flags='A')
ack_resp = scapy.sr1(tcp_ack_pkt, timeout=3, verbose=0)
```
- **Envoi d’un paquet ACK** sur le port 80.  
- **Objectif :** Vérifier si un **firewall bloque les connexions TCP**.  
- Si **aucune réponse**, un **pare-feu bloque peut-être le trafic** :  
  ```python
  print("⚠️  Aucun retour au paquet ACK. Un firewall filtre peut-être les connexions.")
  return detected_os + " - Firewall détecté"
  ```

---

## 🧪 **4.3 Exemple de Résultat**  

### **Commande :**  
```bash
astsu -sO 192.168.1.1
```
### **Sortie attendue :**  
```
Détection de l'OS de la cible 192.168.1.1


        Système d'exploitation détecté : Windows
```
Ou si la cible est un **serveur Linux** :  
```
Détection de l'OS de la cible 192.168.1.1


        Système d'exploitation détecté : Linux
        
```

---

## 🎯 **4.4 Limites de la Détection Basée sur le TTL et TCP**  

La détection basée sur le TTL et le fingerprinting TCP est **puissante**, mais elle a des **limites** :  

### ❌ **Limitations :**  
1. **Influence du Réseau**  
   - Chaque routeur diminue le TTL → Peut fausser l’analyse.  
   - Dans un réseau avec plusieurs sauts, le TTL final peut être **trompeur**.  

2. **Configurations Manuelles**  
   - Certains **administrateurs modifient le TTL par défaut** (ex. : masquer l’OS).  

3. **Pare-feux et IDS**  
   - Certains pare-feux **bloquent ou modifient** les réponses ICMP et TCP.  
   - **Exemple :** Un pare-feu peut répondre avec un **TTL personnalisé**.  

### ✅ **Améliorations Possibles**  
🔹 **Ajouter une analyse des réponses TCP sur plusieurs ports**.  
🔹 **Utiliser un scan ARP pour contourner les pare-feux locaux**.  
🔹 **Détecter les VPN et proxies via le comportement réseau**.

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
from scapy.all import *
import socket

def scan_service(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target, port))

        if result == 0:  # Le port est ouvert
            sock.sendall(b"HELLO\r\n")  # Envoie une requête simple
            response = sock.recv(1024).decode(errors="ignore").strip()  # Récupère la réponse
            sock.close()
            if response:
                return f"[BANNIÈRE] {response}"  # Retourne la bannière du service détecté

    except Exception as e:
        return f"[ERREUR] {e}"  # Capture les erreurs réseau
        
    return "[FERMÉ] Aucun service détecté"
```

---

## 🔍 **5.2 Explication de la Logique**  

### **1️ Connexion au Port Cible**  
```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
result = sock.connect_ex((target, port))
```
- **Crée un socket TCP** pour tester la connexion sur le port spécifié.  
- **Définit un timeout de 2 secondes** pour éviter les blocages en cas de port filtré.  
- **Utilise `connect_ex()`** :
  - Retourne `0` si le port est **ouvert**.  
  - Retourne un **code d’erreur** si le port est **fermé ou filtré**.  

---

### **2️ Envoi d'une Requête et Récupération de la Réponse**  
```python
sock.sendall(b"HELLO\r\n")  # Envoie une requête simple
response = sock.recv(1024).decode(errors="ignore").strip()  # Récupère la réponse
```
- **Envoie un message générique (`HELLO\r\n`)** pour tenter de provoquer une réponse du service.  
- **Lit la réponse (bannière du service)** :  
  - Certains services (FTP, SSH, HTTP...) **répondent automatiquement** avec leur **nom et version**.  

---

### **3️ Fermeture de la Connexion**  
```python
sock.close()
```
- **Libère la ressource socket** pour éviter une saturation des connexions réseau.  

---

### **4️ Gestion des Erreurs**  
```python
except Exception as e:
    return f"[ERREUR] {e}"
```
- Capture **toutes les erreurs possibles** :  
  - Timeout (`socket.timeout`).  
  - Connexion refusée (`ConnectionRefusedError`).  
  - Hôte injoignable (`socket.gaierror`).  

---

## 🧪 **5.3 Tests et Exemples de Résultats**  

### **Commande :**  
```bash
astsu -sC -sV 192.168.1.1
```
- `-sC` : Scan des ports courants.  
- `-sV` : Activation de la détection des services.  

### **Sortie attendue :**  
```

        Scan des ports courants sur 192.168.1.1


        Démarrage - Analyse des port --> TCP <--


[CLOSED]      ------> Port 21
[CLOSED]      ------> Port 22
[CLOSED]      ------> Port 80
[CLOSED]      ------> Port 443
[OPEN]        ------> Port 3306
[CLOSED]      ------> Port 14147
[CLOSED]      ------> Port 2121
[CLOSED]      ------> Port 8080
[CLOSED]      ------> Port 8000


         ✅ Scan terminé :9 ports analysés dont :

                1 - Open
                8 - Closed
                0 - Filtered
                0 - Open/Filtered



        Détection des services actifs sur 192.168.1.1

Port 21   : -
Port 22   : -
Port 80   : -
Port 433  : -
Port 3306 : [BANNIÈRE] FjHost 'Hostname' is not allowed to connect to this MySQL server
Port 8080 : -

```

---

## 🎯 **5.4 Améliorations Futures**  

**Optimiser la détection des bannières** : Essayer différentes **requêtes spécifiques** (`GET / HTTP/1.1`, `USER anonymous` pour FTP, etc.).  
**Ajouter la reconnaissance avancée** des services en **comparant les bannières** à une base de signatures (comme `nmap` avec `nmap-service-probes`).  
**Supporter le scan UDP** (`SOCK_DGRAM`), utile pour les services comme **DNS (53)** ou **SNMP (161)**.  
**Améliorer la gestion des erreurs** pour différencier les ports **fermés** des ports **filtrés** par un pare-feu.  

---

# 🚀 **Phase 6 : Gestion des Arguments et Interface en Ligne de Commande (CLI)**  

La gestion des arguments en ligne de commande est essentielle pour un outil de cybersécurité comme **ASTU**. Cela permet de :  

**Contrôler facilement les fonctionnalités** : scan de ports, détection d'OS, découverte d’hôtes, etc.  
**Personnaliser les scans** : choix du protocole, du timeout, mode Stealth, etc.  
**Automatiser des tâches** : exécuter ASTU dans des scripts ou des pipelines CI/CD.  

Grâce à cette interface CLI, on peut exécuter ASTU avec une simple commande comme :  
```bash
astsu -sC -sV 192.168.1.1
```
🔹 **`-sC`** → Scan des ports courants.  
🔹 **`-sV`** → Détection des services actifs.  

---

## ⚙️ **6.1 Fonction `arguments()` (dans `astsu.py`)**  

### 📄 **Code :**  
```python

def arguments():
    parser = argparse.ArgumentParser(
        description="ASTU - Advanced Security Testing and Scanning Utility",
        usage="\n\t astsu.py [options] [target]",
    )
    
    # Options de scan
    parser.add_argument('-sC', '--scan-common', help="Scan des ports courants", action="count")        
    parser.add_argument('-sA', '--scan-all', help="Scan de tous les ports (0-65535)", action="count")
    parser.add_argument('-sP', '--scan-port', help="Scan d'un port spécifique", type=int)
    parser.add_argument('-d', '--discover', help="Découverte des hôtes sur le réseau", action="count") 
    parser.add_argument('-sO', '--scan-os', help="Détection de l'OS", action="store_true")
    parser.add_argument('-sV', '--scan-service', help="Détection des services actifs", action="store_true")
    
    # Paramètres de configuration
    parser.add_argument('-i', '--interface', help="Interface réseau à utiliser")
    parser.add_argument('-t', '--timeout', help="Timeout pour les requêtes", type=int, default=5)
    parser.add_argument('-p', '--protocol', help="Protocole à utiliser (TCP, UDP, ICMP)", choices=['TCP', 'UDP', 'ICMP'])
    parser.add_argument('-o', '--output', help="Fichier de sortie pour enregistrer les résultats")
    parser.add_argument('-v', '--version', help="Affiche la version", action="store_true")
    parser.add_argument('-st', '--stealth', help='Utiliser le scan stealth (TCP SYN)', action='store_true')
    
    # Cible du scan
    parser.add_argument('Target', nargs='?', help='Adresse IP ou domaine de la cible')
    
    args = parser.parse_args()
    
    # Vérification des arguments : afficher l’aide si aucun argument n’est fourni
    if not (args.scan_common or args.scan_all or args.discover or args.scan_os or args.scan_service or args.version or args.scan_port):
        parser.print_help()
        sys.exit(1)
    
    # Vérification de la cible si nécessaire
    if (args.scan_common or args.scan_all or args.scan_os or args.scan_service) and not args.Target:
        logging.error("Erreur : vous devez spécifier une cible (ex: 192.168.1.1)")
        sys.exit(1)
    
    return args
```

---

## 🔍 **6.2 Analyse des Options d’Arguments**  

### **1️ Scans de Ports :**  
- `-sC` / `--scan-common` → Scan des ports courants (21, 22, 80, 443, etc.).  
- `-sA` / `--scan-all` → Scan de **tous les ports (0-65535)**.  
- `-sP` / `--scan-port` → Scan d’un **port spécifique** (ex: `-sP 80`).  

### **2️ Fonctionnalités Avancées :**  
- `-sO` / `--scan-os` → Détection du **système d’exploitation** de la cible.  
- `-sV` / `--scan-service` → Identification des **services actifs** sur les ports ouverts.  
- `-d` / `--discover` → **Découverte des hôtes** actifs sur le réseau.  

### **3️ Personnalisation des Scans :**  
- `-p` / `--protocol` → Choix du **protocole** (TCP, UDP, ICMP).  
- `-i` / `--interface` → **Spécifier l’interface réseau** à utiliser.  
- `-t` / `--timeout` → Timeout des requêtes (par défaut **5 secondes**).  
- `-st` / `--stealth` → Active le **mode Stealth Scan (TCP SYN)**.  

### **4️ Autres Options :**  
- `-o` / `--output` → Enregistre les résultats dans un fichier.  
- `-v` / `--version` → Affiche la version d’ASTU.  
- `Target` → L’**adresse IP ou le domaine** de la cible.  

---

## 🚀 **6.3 Intégration des Arguments dans le `main`**  

### 📄 **Code :**  
```python
if __name__ == '__main__':
    args, parser = arguments()
    
    print_banner()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80))
        ip = s.getsockname()[0]
        # print(ip)
        s.close()
    except OSError:
        ip = "0.0.0.0"
        print("\n\t⚠️  Connexion Internet absente. L'adresse IP locale ne peut pas être détectée.")
        print("\t⚠️  Assurez-vous d'être connecté au réseau avant de lancer un scan.")
    
        
    scanner = Scanner(
        target=args.Target,
        my_ip=ip,
        protocol=args.protocol if args.protocol else "TCP",
        timeout=args.timeout, 
        interface=args.interface
    )
    
    if args.version:
        print("\n")
        print(f"\t ASTU Version: {__version__}")
        print("\n")
        sys.exit(0) 
    
    if args.output:
        output_file = args.output
        with open(output_file, "w") as f:
            f.write("\t\t===== ASTU Scan Report =====\n\n")

    if args.scan_common:
        print(f"\n\tScan des ports courants sur {args.Target}")
        results = scanner.common_scan(stealth=args.stealth)
        if args.output:
            with open(output_file, "a") as f:
                f.write("\tCommon_scan results\n\n")
                f.write("\n".join(results) + "\n")
                
    if args.scan_all:
        print(f"\n\tScan de tous les ports sur {args.Target}")
        results = scanner.range_scan(start=0, end=65535, stealth=args.stealth)
        if args.output:
            with open(output_file, "a") as f:
                f.write("\tScan_All results\n\n")
                f.write("\n".join(results) + "\n")
                            
    if args.discover:
        results = scanner.discover_net()
        if args.output:
            with open(output_file, "a") as f:
                f.write("\n\t--Network Scan Result--\n\n")
                for line in results:
                    f.write(f"{line} \n")
                f.write("\n")

    if args.scan_os:
        print(f"\n\nDétection de l'OS de la cible {args.Target}\n")
        results = scanner.os_scan()
        if args.output:
            with open(output_file, "a") as f:
                f.write("\tOS detection Results results\n\n")
                f.write(results)

    if args.scan_service:
        print(f"\n\n\tDétection des services actifs sur {args.Target}\n")
        results = scanner.service_scan(args.Target)
        print("\n")
        if args.output:
            with open(output_file, "a") as f:
                f.write("\n".join(results) + "\n")

    if args.scan_port:
```

---

## 📊 **6.4 Exemples d’Utilisation**  

### **1️ Scan des Ports Courants sur une Cible**
```bash
astsu -sC 192.168.1.1
```
➡ Scanne les **ports les plus utilisés** (HTTP, SSH, FTP, etc.).  

### **2️ Scan Complet de Tous les Ports**
```bash
astsu -sA 192.168.1.1
```
➡ Scanne **tous les ports TCP (0-65535)**.  

### **3️ Scan d’un Port Spécifique**
```bash
astsu -sP 22 192.168.1.1
```
➡ Vérifie si le **port 22 (SSH)** est ouvert.  

### **4️ Découverte des Hôtes sur le Réseau**
```bash
astsu -d
```
➡ Affiche les **machines connectées au réseau local**.  

### **5️ Détection de l’OS de la Cible**
```bash
astsu -sO 192.168.1.1
```
➡ Essaye d’identifier **le système d’exploitation** via ICMP et TCP.  

---
