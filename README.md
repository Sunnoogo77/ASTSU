# **📌 README.md pour ASTSU**  
*(Un fichier clair et concis pour présenter le projet.)*  

---

## **🛠 ASTSU - Advanced Security Testing & Scanning Utility**  
🔍 Outil avancé de scan réseau et de test de sécurité  

![ASTSU Logo](.img/ASTSU_bg.jpg)  

---

## **📖 Description**  
**ASTSU** est un outil de scan réseau développé en Python, permettant d'effectuer diverses analyses de sécurité, notamment :  
✅ **Scan de ports TCP/UDP** (ouvert, fermé, filtré)  
✅ **Détection du système d’exploitation** via fingerprinting  
✅ **Scan furtif (Stealth Mode)** pour contourner certains pare-feux  
✅ **Découverte des hôtes actifs sur un réseau**  
✅ **Détection des services actifs et bannières**  

Pour une explication détaillée des fonctionnalités, consultez **`Plan.md`**.  

---

## **📥 Installation**  

### 🔹 **Linux**  
```bash
git clone https://github.com/Sunnoogo77/ASTSU.git
cd ASTSU
chmod +x install.py
sudo python3 install.py
```

### 🔹 **Windows**  
```powershell
git clone https://github.com/Sunnoogo77/ASTSU.git
cd ASTSU
python install.py
```

---

## **🚀 Utilisation**  
Lancez ASTSU en ligne de commande :  
```bash
astsu -h  # Affiche l'aide
```

### **Exemples de scan**  
🔹 **Scan des ports courants**  
```bash
astsu -sC 192.168.1.1
```

🔹 **Scan furtif en mode Stealth**  
```bash
astsu -sC -st 192.168.1.1
```

🔹 **Détection de l'OS**  
```bash
astsu -sO 192.168.1.1
```

🔹 **Scan d’un port spécifique**  
```bash
astsu -sP 443 192.168.1.1
```

🔹 **Scan de tous les ports (0-65535)**  
```bash
astsu -sA 192.168.1.1
```

🔹 **Découverte des hôtes actifs sur le réseau**  
```bash
astsu -d
```

🔹 **Détection des services actifs**  
```bash
astsu -sV 192.168.1.1
```

---

## **🖥️ Systèmes Supportés**  
✅ Windows  
✅ Linux  
⏳ macOS *(non testé, peut nécessiter des ajustements)*  

---

## **📜 Licence**  
🔓 Ce projet est sous licence **MIT**. Vous pouvez l'utiliser, le modifier et le partager librement.  

---

## **💡 Remarque**  
Pour une documentation plus détaillée, consultez le fichier [**`Plan.md`**](Plan.md).  


## **📖 À propos du projet**  
Ce projet est une **reproduction améliorée** d’un outil existant : **[ASTSU de ReddyyZ](https://github.com/ReddyyZ/astsu)**.  
L’objectif était de **comprendre son fonctionnement**, d’y apporter des **améliorations**
---
