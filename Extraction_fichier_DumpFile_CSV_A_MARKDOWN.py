#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import filedialog, messagebox
import matplotlib.pyplot as plt
import os

def lire_fichier_csv(nom_fichier):
    """
    Cette fonction lit le fichier CSV
    """
    print(f"Lecture du fichier : {nom_fichier}")
    
    # J'ouvre le fichier
    fichier = open(nom_fichier, 'r', encoding='utf-8')
    lignes = fichier.readlines()
    fichier.close()
    
    # Je saute la première ligne (les titres)
    donnees = []
    for i in range(1, len(lignes)):
        ligne = lignes[i].strip()
        if ligne != '':  # ignorer les lignes vides
            colonnes = ligne.split(';')
            donnees.append(colonnes)
    
    print(f"J'ai lu {len(donnees)} paquets")
    return donnees

def analyser_donnees(donnees):
    """
    Ici je compte tout ce dont j'ai besoin pour l'analyse
    """
    print("Analyse en cours...")
    
    # Créer mes dictionnaires pour compter
    paquets_par_ip = {}
    octets_par_ip = {}
    paquets_par_heure = {}
    ports_par_ip = {}
    syn_par_ip = {}
    paquets_par_protocole = {}
    
    total = len(donnees)
    
    # Je parcours chaque ligne
    for ligne in donnees:
        # J'extrais les infos importantes
        timestamp = ligne[0]
        protocole = ligne[1]
        ip_src = ligne[2]
        port_dst = ligne[5]
        flags = ligne[6]
        length = ligne[10]
        
        # Compter les paquets par IP source
        if ip_src in paquets_par_ip:
            paquets_par_ip[ip_src] = paquets_par_ip[ip_src] + 1
        else:
            paquets_par_ip[ip_src] = 1
        
        # Compter les octets (un peu compliqué car il faut nettoyer)
        if length != 'N/A' and length != '':
            length = length.replace(':', '').replace(',', '').strip()
            if length.isdigit():
                octets = int(length)
            else:
                octets = 0
        else:
            octets = 0
        
        if ip_src in octets_par_ip:
            octets_par_ip[ip_src] = octets_par_ip[ip_src] + octets
        else:
            octets_par_ip[ip_src] = octets
        
        # Extraire l'heure (format HH:MM:SS)
        heure = timestamp.split(':')[0]
        if heure in paquets_par_heure:
            paquets_par_heure[heure] = paquets_par_heure[heure] + 1
        else:
            paquets_par_heure[heure] = 1
        
        # Compter par protocole
        if protocole in paquets_par_protocole:
            paquets_par_protocole[protocole] = paquets_par_protocole[protocole] + 1
        else:
            paquets_par_protocole[protocole] = 1
        
        # Pour détecter les scans de ports plus tard
        if ip_src not in ports_par_ip:
            ports_par_ip[ip_src] = []
        
        if port_dst not in ports_par_ip[ip_src] and port_dst != 'N/A':
            ports_par_ip[ip_src].append(port_dst)
        
        # Compter les paquets SYN (pour détecter les attaques)
        if flags == 'S':
            if ip_src in syn_par_ip:
                syn_par_ip[ip_src] = syn_par_ip[ip_src] + 1
            else:
                syn_par_ip[ip_src] = 1
    
    # Je mets tout dans un dictionnaire
    resultats = {
        'total': total,
        'paquets_par_ip': paquets_par_ip,
        'octets_par_ip': octets_par_ip,
        'paquets_par_heure': paquets_par_heure,
        'ports_par_ip': ports_par_ip,
        'syn_par_ip': syn_par_ip,
        'paquets_par_protocole': paquets_par_protocole
    }
    
    print("Analyse terminée !")
    return resultats

def detecter_problemes(resultats):
    """
    Cette fonction cherche les anomalies dans le trafic
    """
    print("Je cherche les anomalies...")
    
    problemes = []
    
    # Vérifier s'il y a des SYN FLOOD
    # (une IP qui envoie beaucoup de SYN = suspect)
    for ip in resultats['syn_par_ip']:
        nb_syn = resultats['syn_par_ip'][ip]
        if nb_syn > 100:  # seuil fixé à 100
            problemes.append({
                'type': 'SYN FLOOD',
                'ip': ip,
                'nombre': nb_syn,
                'gravite': 'ELEVEE'
            })
    
    # Vérifier s'il y a des scans de ports
    # (une IP qui contacte plein de ports différents)
    for ip in resultats['ports_par_ip']:
        nb_ports = len(resultats['ports_par_ip'][ip])
        if nb_ports > 50:  # seuil à 50 ports
            problemes.append({
                'type': 'PORT SCAN',
                'ip': ip,
                'nombre': nb_ports,
                'gravite': 'MOYENNE'
            })
    
    # Vérifier s'il y a du flood
    # (une IP qui génère trop de trafic)
    for ip in resultats['paquets_par_ip']:
        nb_paquets = resultats['paquets_par_ip'][ip]
        pourcentage = (nb_paquets * 100) / resultats['total']
        if pourcentage > 40:
            problemes.append({
                'type': 'FLOOD',
                'ip': ip,
                'nombre': nb_paquets,
                'gravite': 'ELEVEE'
            })
    
    print(f"J'ai trouvé {len(problemes)} problème(s)")
    return problemes

def creer_image_anomalies(problemes, nom_fichier):
    """
    Créer l'image qui montre les anomalies détectées
    """
    print("Création de l'image des anomalies...")
    
    plt.figure(figsize=(12, 6))
    
    if len(problemes) == 0:
        # Pas de problème = message positif
        plt.text(0.5, 0.5, 'Aucune anomalie detectee', 
                ha='center', va='center', fontsize=20, color='green')
        plt.text(0.5, 0.3, 'Le trafic semble normal', 
                ha='center', va='center', fontsize=14)
    else:
        # Il y a des problèmes, je les affiche
        titre = f'{len(problemes)} Anomalie(s) Detectee(s)'
        plt.text(0.5, 0.95, titre, 
                ha='center', va='top', fontsize=18, color='red')
        
        # J'affiche chaque anomalie
        y_position = 0.75
        for pb in problemes:
            # Le type
            texte1 = f"TYPE: {pb['type']}"
            plt.text(0.1, y_position, texte1, fontsize=12, weight='bold')
            
            # L'IP
            texte2 = f"IP: {pb['ip']}"
            plt.text(0.1, y_position - 0.05, texte2, fontsize=10)
            
            # La gravité
            texte3 = f"Gravite: {pb['gravite']}"
            if pb['gravite'] == 'ELEVEE':
                couleur = 'red'
            else:
                couleur = 'orange'
            plt.text(0.1, y_position - 0.10, texte3, fontsize=10, color=couleur)
            
            # Le nombre
            texte4 = f"Nombre: {pb['nombre']}"
            plt.text(0.1, y_position - 0.15, texte4, fontsize=10)
            
            # Une petite ligne pour séparer
            plt.plot([0.05, 0.95], [y_position - 0.20, y_position - 0.20], 'k-', linewidth=1)
            
            y_position = y_position - 0.25
    
    plt.axis('off')
    plt.savefig(nom_fichier, dpi=100, bbox_inches='tight')
    plt.close()
    print(f"OK ! Image créée : {nom_fichier}")

def creer_image_trafic(resultats, problemes, nom_fichier):
    """
    Créer l'image avec l'analyse du trafic
    """
    print("Création de l'image du trafic...")
    
    fig = plt.figure(figsize=(14, 10))
    
    # === Premier graphique : Trafic par heure ===
    ax1 = plt.subplot(3, 1, 1)
    
    # Préparer les données (trier les heures)
    heures = []
    nb_paquets = []
    for heure in sorted(resultats['paquets_par_heure'].keys()):
        heures.append(heure)
        nb_paquets.append(resultats['paquets_par_heure'][heure])
    
    # Tracer
    ax1.plot(heures, nb_paquets, marker='o', color='blue', linewidth=2)
    ax1.set_xlabel('Heure')
    ax1.set_ylabel('Nombre de paquets')
    ax1.set_title('Trafic Reseau par Heure')
    ax1.grid(True)
    
    # === Deuxième graphique : Top 5 IP ===
    ax2 = plt.subplot(3, 1, 2)
    
    # Je trie les IP par nombre de paquets
    liste_ip = []
    for ip in resultats['paquets_par_ip']:
        nb = resultats['paquets_par_ip'][ip]
        liste_ip.append((ip, nb))
    
    # Trier du plus grand au plus petit
    liste_ip.sort(key=lambda x: x[1], reverse=True)
    
    # Prendre les 5 premiers
    top5_ip = []
    top5_nb = []
    for i in range(min(5, len(liste_ip))):
        top5_ip.append(liste_ip[i][0])
        top5_nb.append(liste_ip[i][1])
    
    # Mettre en rouge les IP suspectes
    couleurs = []
    for ip in top5_ip:
        est_suspect = False
        for pb in problemes:
            if pb['ip'] == ip:
                est_suspect = True
        
        if est_suspect:
            couleurs.append('red')
        else:
            couleurs.append('blue')
    
    # Tracer
    ax2.barh(top5_ip, top5_nb, color=couleurs)
    ax2.set_xlabel('Nombre de paquets')
    ax2.set_title('Top 5 des IP Sources')
    ax2.grid(axis='x')
    
    # === Troisième graphique : Volume par IP ===
    ax3 = plt.subplot(3, 1, 3)
    
    # Trier par volume d'octets
    liste_octets = []
    for ip in resultats['octets_par_ip']:
        octets = resultats['octets_par_ip'][ip]
        liste_octets.append((ip, octets))
    
    liste_octets.sort(key=lambda x: x[1], reverse=True)
    
    # Top 5
    top5_ip_oct = []
    top5_octets = []
    for i in range(min(5, len(liste_octets))):
        top5_ip_oct.append(liste_octets[i][0])
        # Convertir en Ko (diviser par 1024)
        top5_octets.append(liste_octets[i][1] / 1024)
    
    # Tracer
    ax3.bar(range(len(top5_ip_oct)), top5_octets, color='green')
    ax3.set_xticks(range(len(top5_ip_oct)))
    ax3.set_xticklabels(top5_ip_oct, rotation=45, ha='right')
    ax3.set_xlabel('IP Source')
    ax3.set_ylabel('Volume (Ko)')
    ax3.set_title('Volume de Donnees par IP')
    ax3.grid(axis='y')
    
    plt.tight_layout()
    plt.savefig(nom_fichier, dpi=100, bbox_inches='tight')
    plt.close()
    print(f"OK ! Image créée : {nom_fichier}")

def creer_image_protocoles(resultats, nom_fichier):
    """
    Créer le camembert des protocoles
    """
    print("Création de l'image des protocoles...")
    
    plt.figure(figsize=(10, 8))
    
    # Récupérer les protocoles et leur nombre
    protocoles = []
    nb_protocoles = []
    
    for proto in resultats['paquets_par_protocole']:
        protocoles.append(proto)
        nb_protocoles.append(resultats['paquets_par_protocole'][proto])
    
    # Quelques couleurs simples
    couleurs = ['blue', 'red', 'green', 'orange', 'purple', 'cyan']
    
    # Créer le camembert
    plt.pie(nb_protocoles, labels=protocoles, autopct='%1.1f%%', colors=couleurs)
    plt.title('Distribution des Protocoles Reseau')
    
    plt.savefig(nom_fichier, dpi=100, bbox_inches='tight')
    plt.close()
    print(f"OK ! Image créée : {nom_fichier}")

def traiter_csv(chemin):
    """
    La fonction principale qui fait tout le travail
    """
    print("\n========== DEBUT ==========\n")
    
    # Créer le dossier si il existe pas
    if not os.path.exists('resultats_interface'):
        os.makedirs('resultats_interface')
    
    # Étape 1 : Lire le CSV
    donnees = lire_fichier_csv(chemin)
    
    # Étape 2 : Analyser
    resultats = analyser_donnees(donnees)
    
    # Étape 3 : Chercher les problèmes
    problemes = detecter_problemes(resultats)
    
    # Étape 4 : Créer les images
    creer_image_anomalies(problemes, 'resultats_interface/anomalies.png')
    creer_image_trafic(resultats, problemes, 'resultats_interface/analyse_trafic.png')
    creer_image_protocoles(resultats, 'resultats_interface/protocoles.png')
    
    print("\n========== TERMINE ==========\n")
    
    # Afficher un message à l'utilisateur
    messagebox.showinfo(
        "Termine !",
        f"Analyse terminee !\n\n"
        f"Paquets analyses : {len(donnees)}\n"
        f"Anomalies trouvees : {len(problemes)}\n"
        f"Protocoles detectes : {len(resultats['paquets_par_protocole'])}\n\n"
        f"Les images sont dans le dossier resultats_interface/"
    )

def bouton_choisir():
    """
    Quand on clique sur le bouton
    """
    fichier = filedialog.askopenfilename(
        title="Choisir le fichier CSV",
        filetypes=[("Fichiers CSV", "*.csv"), ("Tous les fichiers", "*.*")]
    )
    
    if fichier:
        traiter_csv(fichier)

# ========================================
# INTERFACE GRAPHIQUE
# ========================================

fenetre = tk.Tk()
fenetre.title("Analyseur Reseau")
fenetre.geometry("450x250")

# Le titre
titre = tk.Label(
    fenetre, 
    text="Analyseur de Trafic Reseau", 
    font=("Arial", 14, "bold")
)
titre.pack(pady=20)

# La description
description = tk.Label(
    fenetre,
    text="Ce programme genere 3 images :\n"
         "- Les anomalies detectees\n"
         "- L'analyse du trafic\n"
         "- La distribution des protocoles",
    font=("Arial", 10)
)
description.pack(pady=15)

# Le bouton pour choisir le fichier
bouton = tk.Button(
    fenetre,
    text="Choisir un fichier CSV",
    command=bouton_choisir,
    bg="#27ae60",
    fg="white",
    font=("Arial", 12),
    padx=20,
    pady=10
)
bouton.pack(pady=15)

# Le bouton pour quitter
bouton_quit = tk.Button(
    fenetre,
    text="Quitter",
    command=fenetre.quit,
    bg="#e74c3c",
    fg="white",
    font=("Arial", 10),
    padx=20,
    pady=5
)
bouton_quit.pack(pady=10)

# Lancer le programme
fenetre.mainloop()