#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import filedialog, messagebox

def trouver_ip_et_port(texte):
    """
    Fonction qui sépare une IP et un port depuis un texte
    Exemple : "192.168.1.10.80" donne IP="192.168.1.10" et port="80"
    """
    # On enlève les caractères bizarres
    texte = texte.replace(':', '')
    texte = texte.replace('>', '')
    texte = texte.strip()
    
    # On cherche le dernier point pour séparer l'IP du port
    position = texte.rfind('.')
    
    if position == -1:
        # Pas de point trouvé
        return texte, 'N/A'
    
    # On sépare en deux parties
    ip = texte[:position]
    port = texte[position + 1:]
    
    # Si le port est un nom (ssh, http...), on le convertit
    if port == 'ssh':
        port = '22'
    elif port == 'http':
        port = '80'
    elif port == 'https':
        port = '443'
    
    return ip, port


def chercher_valeur(liste_mots, mot_a_chercher):
    """
    Cherche un mot dans une liste et retourne la valeur qui suit
    Par exemple : chercher "seq" dans ["IP", "seq", "12345"] retourne "12345"
    """
    # On parcourt tous les mots
    for i in range(len(liste_mots)):
        if liste_mots[i] == mot_a_chercher:
            # On a trouvé le mot, on prend le suivant
            if i + 1 < len(liste_mots):
                valeur = liste_mots[i + 1]
                # On enlève la virgule si elle existe
                valeur = valeur.replace(',', '')
                
                # Pour seq, on garde seulement le premier nombre
                if mot_a_chercher == 'seq' and ':' in valeur:
                    valeur = valeur.split(':')[0]
                
                return valeur
    
    return 'N/A'


def extraire_flags(ligne_complete):
    """
    Extrait les flags TCP qui sont entre crochets [...]
    Exemple : "Flags [S.]" retourne "S."
    """
    # On cherche "Flags [" dans la ligne
    debut = ligne_complete.find('Flags [')
    
    if debut == -1:
        return 'N/A'
    
    # On avance jusqu'après "Flags ["
    debut = debut + 7
    
    # On cherche le crochet fermant ]
    fin = ligne_complete.find(']', debut)
    
    if fin > debut:
        return ligne_complete[debut:fin]
    else:
        return 'N/A'


def analyser_ligne(ligne):
    """
    Fonction principale qui analyse une ligne du fichier tcpdump
    Elle extrait toutes les informations importantes
    """
    # On vérifie que c'est bien une ligne avec des données IP
    if 'IP' not in ligne:
        return None
    
    # On ignore les lignes qui commencent par 0x (données hexadécimales)
    if ligne.strip().startswith('0x'):
        return None
    
    # On découpe la ligne en mots séparés par des espaces
    mots = ligne.split()
    
    # On vérifie qu'on a assez de mots
    if len(mots) < 5:
        return None
    
    # L'heure est le premier mot
    heure = mots[0]
    
    # Le protocole est le deuxième mot
    protocole = mots[1]
    
    # L'IP source et son port sont dans le mot 2
    ip_source, port_source = trouver_ip_et_port(mots[2])
    
    # L'IP destination est après le symbole ">"
    # Elle peut être au mot 3 ou 4
    if mots[3] == '>':
        ip_destination, port_destination = trouver_ip_et_port(mots[4])
    else:
        ip_destination, port_destination = trouver_ip_et_port(mots[3])
    
    # Les flags TCP
    flags = extraire_flags(ligne)
    
    # Les numéros de séquence et acquittement
    seq = chercher_valeur(mots, 'seq')
    ack = chercher_valeur(mots, 'ack')
    
    # La taille de la fenêtre
    window = chercher_valeur(mots, 'win')
    
    # La longueur du paquet
    length = chercher_valeur(mots, 'length')
    
    # Nettoyer la longueur (enlever les ":" si présents)
    if length != 'N/A' and ':' in length:
        length = length.split(':')[0]
    
    # On retourne toutes les infos dans un dictionnaire
    infos = {
        'heure': heure,
        'protocole': protocole,
        'ip_source': ip_source,
        'port_source': port_source,
        'ip_destination': ip_destination,
        'port_destination': port_destination,
        'flags': flags,
        'seq': seq,
        'ack': ack,
        'window': window,
        'length': length
    }
    
    return infos

def convertir_fichier(fichier_entree, fichier_sortie):
    """
    Fonction qui lit le fichier tcpdump et crée le fichier CSV
    """
    print("Démarrage de la conversion...")
    print(f"Lecture : {fichier_entree}")
    
    # Liste pour stocker tous les paquets
    paquets = []
    
    # Compteurs
    nb_lignes_lues = 0
    nb_lignes_ignorees = 0
    
    # Ouvrir le fichier en lecture
    fichier = open(fichier_entree, 'r', encoding='utf-8', errors='ignore')
    
    # Lire ligne par ligne
    for ligne in fichier:
        nb_lignes_lues += 1
        
        # Analyser la ligne
        resultat = analyser_ligne(ligne)
        
        # Si on a trouvé des infos, on les garde
        if resultat != None:
            paquets.append(resultat)
        else:
            nb_lignes_ignorees += 1
    
    # Fermer le fichier
    fichier.close()
    
    print(f"Lignes lues : {nb_lignes_lues}")
    print(f"Paquets extraits : {len(paquets)}")
    print(f"Lignes ignorées : {nb_lignes_ignorees}")
    
    # Si on a des paquets, on crée le CSV
    if len(paquets) > 0:
        # Ouvrir le fichier CSV en écriture
        fichier_csv = open(fichier_sortie, 'w', encoding='utf-8')
        
        # Écrire la première ligne (en-têtes)
        fichier_csv.write("Timestamp;Protocole;IP Source;Port Source;")
        fichier_csv.write("IP Destination;Port Destination;Flags;")
        fichier_csv.write("Seq;Ack;Window;Length\n")
        
        # Écrire chaque paquet
        for paquet in paquets:
            ligne = f"{paquet['heure']};{paquet['protocole']};"
            ligne += f"{paquet['ip_source']};{paquet['port_source']};"
            ligne += f"{paquet['ip_destination']};{paquet['port_destination']};"
            ligne += f"{paquet['flags']};{paquet['seq']};{paquet['ack']};"
            ligne += f"{paquet['window']};{paquet['length']}\n"
            
            fichier_csv.write(ligne)
        
        # Fermer le fichier CSV
        fichier_csv.close()
        
        print(f"Fichier créé : {fichier_sortie}")
        return len(paquets)
    
    else:
        print("Aucun paquet trouvé !")
        return 0

def bouton_choisir():
    """
    Fonction appelée quand on clique sur le bouton
    """
    # Demander quel fichier ouvrir
    fichier_txt = filedialog.askopenfilename(
        title="Choisir le fichier tcpdump",
        filetypes=[("Fichiers texte", "*.txt"), ("Tous", "*.*")]
    )
    
    # Si l'utilisateur a choisi un fichier
    if fichier_txt:
        texte_info.config(text=f"Fichier : {fichier_txt}")
        
        # Demander où enregistrer le CSV
        fichier_csv = filedialog.asksaveasfilename(
            title="Enregistrer le CSV",
            defaultextension=".csv",
            filetypes=[("Fichiers CSV", "*.csv")]
        )
        
        if fichier_csv:
            # Lancer la conversion
            nb = convertir_fichier(fichier_txt, fichier_csv)
            
            if nb > 0:
                # Message de succès
                messagebox.showinfo(
                    "Terminé",
                    f"Conversion réussie !\n\n{nb} paquets extraits\n\nFichier : {fichier_csv}"
                )
                texte_info.config(text="✓ Conversion terminée")
            else:
                messagebox.showerror("Erreur", "Aucune donnée trouvée")
                texte_info.config(text="Aucune donnée")


def bouton_quitter():
    """
    Fonction pour fermer le programme
    """
    fenetre.destroy()

# Créer la fenêtre
fenetre = tk.Tk()
fenetre.title("SAE 1.05 - Conversion tcpdump")
fenetre.geometry("450x250")

# Titre
titre = tk.Label(fenetre, text="Convertisseur tcpdump → CSV", font=("Arial", 14, "bold"))
titre.pack(pady=20)

# Bouton pour choisir le fichier
bouton = tk.Button(
    fenetre,
    text="Choisir un fichier",
    command=bouton_choisir,
    bg="#3498db",
    fg="white",
    font=("Arial", 10),
    padx=20,
    pady=10
)
bouton.pack(pady=15)

# Texte d'information
texte_info = tk.Label(fenetre, text="Aucun fichier sélectionné", fg="gray")
texte_info.pack(pady=10)

# Bouton quitter
bouton_quit = tk.Button(fenetre, text="Quitter", command=bouton_quitter, bg="#95a5a6", fg="white")
bouton_quit.pack(pady=15)

# Lancer la fenêtre
fenetre.mainloop()