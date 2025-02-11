import platform
import os
import shutil

ASTSU_DIR_LINUX = "/usr/share/astsu"
ASTSU_DIR_WINDOWS = "C:\\astsu"

machine_os = platform.system()

def install_on_linux():
    """ Installation sous Linux """
    try:
        if not os.path.exists(ASTSU_DIR_LINUX):
            os.makedirs(ASTSU_DIR_LINUX)
        
        # Copie des fichiers dans le dossier cible
        for item in os.listdir():
            src = os.path.join(os.getcwd(), item)
            dst = os.path.join(ASTSU_DIR_LINUX, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)
        
        # Création du lien symbolique pour exécuter ASTSU depuis n'importe où
        if not os.path.exists("/usr/bin/astsu"):
            os.symlink(f"{ASTSU_DIR_LINUX}/astsu.py", "/usr/bin/astsu")
        
        print(" ASTSU a été installé avec succès sur Linux !")

    except Exception as e:
        print(f" Erreur lors de l'installation sur Linux : {e}")

def install_on_windows():
    """ Installation sous Windows """
    try:
        if not os.path.exists(ASTSU_DIR_WINDOWS):
            os.makedirs(ASTSU_DIR_WINDOWS)

        # Copie des fichiers dans le dossier cible
        for item in os.listdir():
            src = os.path.join(os.getcwd(), item)
            dst = os.path.join(ASTSU_DIR_WINDOWS, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)

        # Création d'un script batch pour exécuter ASTSU depuis CMD
        batch_file = "C:\\Windows\\System32\\astsu.bat"
        if not os.path.exists(batch_file):
            with open(batch_file, "w") as f:
                f.write(f'@echo off\npython "{ASTSU_DIR_WINDOWS}\\astsu.py" %*\n')

        print("\n ASTSU a été installé avec succès sur Windows ! \n")

    except Exception as e:
        print(f" Erreur lors de l'installation sur Windows : {e}")

if machine_os == "Linux":
    install_on_linux()
elif machine_os == "Windows":
    install_on_windows()
else:
    print("[-] Système d'exploitation non reconnu. Installation annulée.")
