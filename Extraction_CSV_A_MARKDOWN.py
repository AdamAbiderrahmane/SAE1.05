#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import filedialog, messagebox
import matplotlib.pyplot as plt
import os


def lire_fichier_csv(nom_fichier):
    """Lit le fichier CSV et retourne les lignes"""
    fichier = open(nom_fichier, 'r', encoding='utf-8')
    lignes_brutes = fichier.readlines()
    fichier.close()
    
    # On saute la première ligne (en-têtes)
    lignes = []
    for i in range(1, len(lignes_brutes)):
        ligne = lignes_brutes[i].strip()
        if ligne != '':
            colonnes = ligne.split(';')
            lignes.append(colonnes)
    
    print(f"J'ai lu {len(lignes)} paquets")
    return lignes


def analyser_donnees(donnees):
    """Analyse les paquets et compte tout"""
    print("Analyse en cours...")
    
    # Mes dictionnaires pour stocker les résultats
    paquets_par_ip = {}
    octets_par_ip = {}
    paquets_par_heure = {}
    ports_par_ip = {}
    syn_par_ip = {}
    paquets_par_protocole = {}
    
    # Je parcours chaque paquet
    for ligne in donnees:
        # Gestion des lignes avec taille variable
        if len(ligne) < 11:
            for j in range(11 - len(ligne)):
                ligne.append('N/A')
        
        timestamp = ligne[0]
        protocole = ligne[1]
        ip_src = ligne[2]
        port_dst = ligne[5]
        flags = ligne[6]
        length = ligne[10]
        
        # Compter paquets par IP
        if ip_src in paquets_par_ip:
            paquets_par_ip[ip_src] = paquets_par_ip[ip_src] + 1
        else:
            paquets_par_ip[ip_src] = 1
        
        # Compter octets par IP
        octets = 0
        if length != 'N/A' and length != '':
            length = length.replace(':', '')
            length = length.replace(',', '')
            length = length.strip()
            if length.isdigit():
                octets = int(length)
        
        if ip_src in octets_par_ip:
            octets_par_ip[ip_src] = octets_par_ip[ip_src] + octets
        else:
            octets_par_ip[ip_src] = octets
        
        # Extraire l'heure
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
        
        # Stocker les ports par IP
        if ip_src not in ports_par_ip:
            ports_par_ip[ip_src] = []
        
        if port_dst not in ports_par_ip[ip_src] and port_dst != 'N/A':
            ports_par_ip[ip_src].append(port_dst)
        
        # Compter les paquets SYN
        if flags == 'S':
            if ip_src in syn_par_ip:
                syn_par_ip[ip_src] = syn_par_ip[ip_src] + 1
            else:
                syn_par_ip[ip_src] = 1
    
    print("Analyse terminée !")
    
    resultats = {
        'total': len(donnees),
        'paquets_par_ip': paquets_par_ip,
        'octets_par_ip': octets_par_ip,
        'paquets_par_heure': paquets_par_heure,
        'ports_par_ip': ports_par_ip,
        'syn_par_ip': syn_par_ip,
        'paquets_par_protocole': paquets_par_protocole
    }
    
    return resultats


def detecter_problemes(resultats):
    """Détecte les anomalies réseau"""
    print("Je cherche les anomalies...")
    problemes = []
    
    # Vérifier les SYN FLOOD
    for ip in resultats['syn_par_ip']:
        nb_syn = resultats['syn_par_ip'][ip]
        if nb_syn > 100:
            probleme = {
                'type': 'SYN FLOOD',
                'ip': ip,
                'nombre': nb_syn,
                'gravite': 'ELEVEE'
            }
            problemes.append(probleme)
    
    # Vérifier les scans de ports
    for ip in resultats['ports_par_ip']:
        nb_ports = len(resultats['ports_par_ip'][ip])
        if nb_ports > 50:
            probleme = {
                'type': 'PORT SCAN',
                'ip': ip,
                'nombre': nb_ports,
                'gravite': 'MOYENNE'
            }
            problemes.append(probleme)
    
    # Vérifier le flood de paquets
    for ip in resultats['paquets_par_ip']:
        nb_paquets = resultats['paquets_par_ip'][ip]
        pourcentage = (nb_paquets * 100) / resultats['total']
        if pourcentage > 40:
            probleme = {
                'type': 'FLOOD',
                'ip': ip,
                'nombre': nb_paquets,
                'gravite': 'ELEVEE'
            }
            problemes.append(probleme)
    
    print(f"J'ai trouvé {len(problemes)} problème(s)")
    return problemes


def creer_image_anomalies(problemes, nom_fichier):
    """Crée l'image des anomalies détectées"""
    print("Création de l'image des anomalies...")
    plt.figure(figsize=(12, 6))
    
    if len(problemes) == 0:
        plt.text(0.5, 0.5, 'Aucune anomalie detectee', 
                ha='center', va='center', fontsize=20, color='green')
        plt.text(0.5, 0.3, 'Le trafic semble normal', 
                ha='center', va='center', fontsize=14)
    else:
        titre = str(len(problemes)) + ' Anomalie(s) Detectee(s)'
        plt.text(0.5, 0.95, titre, ha='center', va='top', fontsize=18, color='red')
        
        y = 0.75
        for pb in problemes:
            if pb['gravite'] == 'ELEVEE':
                couleur = 'red'
            else:
                couleur = 'orange'
            
            plt.text(0.1, y, "TYPE: " + pb['type'], fontsize=12, weight='bold')
            plt.text(0.1, y - 0.05, "IP: " + pb['ip'], fontsize=10)
            plt.text(0.1, y - 0.10, "Gravite: " + pb['gravite'], fontsize=10, color=couleur)
            plt.text(0.1, y - 0.15, "Nombre: " + str(pb['nombre']), fontsize=10)
            plt.plot([0.05, 0.95], [y - 0.20, y - 0.20], 'k-', linewidth=1)
            y = y - 0.25
    
    plt.axis('off')
    plt.savefig(nom_fichier, dpi=100, bbox_inches='tight')
    plt.close()
    print(f"OK ! Image créée : {nom_fichier}")


def creer_image_trafic(resultats, problemes, nom_fichier):
    """Crée l'image d'analyse du trafic"""
    print("Création de l'image du trafic...")
    
    fig = plt.figure(figsize=(14, 10))
    
    # Graphique 1: Trafic par heure
    ax1 = plt.subplot(3, 1, 1)
    
    heures = []
    for h in resultats['paquets_par_heure']:
        heures.append(h)
    heures.sort()
    
    nb_paquets = []
    for h in heures:
        nb_paquets.append(resultats['paquets_par_heure'][h])
    
    ax1.plot(heures, nb_paquets, marker='o', color='blue', linewidth=2)
    ax1.set_xlabel('Heure')
    ax1.set_ylabel('Nombre de paquets')
    ax1.set_title('Trafic Reseau par Heure')
    ax1.grid(True)
    
    # Graphique 2: Top 5 IP
    ax2 = plt.subplot(3, 1, 2)
    
    liste_ip = []
    for ip in resultats['paquets_par_ip']:
        liste_ip.append((ip, resultats['paquets_par_ip'][ip]))
    
    liste_ip.sort(key=lambda x: x[1], reverse=True)
    
    top5_ip = []
    top5_nb = []
    for i in range(min(5, len(liste_ip))):
        top5_ip.append(liste_ip[i][0])
        top5_nb.append(liste_ip[i][1])
    
    # Colorer les IP suspectes en rouge
    couleurs = []
    for ip in top5_ip:
        est_suspect = False
        for pb in problemes:
            if pb['ip'] == ip:
                est_suspect = True
                break
        
        if est_suspect:
            couleurs.append('red')
        else:
            couleurs.append('blue')
    
    ax2.barh(top5_ip, top5_nb, color=couleurs)
    ax2.set_xlabel('Nombre de paquets')
    ax2.set_title('Top 5 des IP Sources')
    ax2.grid(axis='x')
    
    # Graphique 3: Volume par IP
    ax3 = plt.subplot(3, 1, 3)
    
    liste_octets = []
    for ip in resultats['octets_par_ip']:
        liste_octets.append((ip, resultats['octets_par_ip'][ip]))
    
    liste_octets.sort(key=lambda x: x[1], reverse=True)
    
    top5_ip_oct = []
    top5_octets = []
    for i in range(min(5, len(liste_octets))):
        top5_ip_oct.append(liste_octets[i][0])
        # Convertir en Ko
        top5_octets.append(liste_octets[i][1] / 1024)
    
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
    """Crée le camembert des protocoles"""
    print("Création de l'image des protocoles...")
    plt.figure(figsize=(10, 8))
    
    protocoles = []
    nb_protocoles = []
    for proto in resultats['paquets_par_protocole']:
        protocoles.append(proto)
        nb_protocoles.append(resultats['paquets_par_protocole'][proto])
    
    couleurs = ['blue', 'red', 'green', 'orange', 'purple', 'cyan']
    plt.pie(nb_protocoles, labels=protocoles, autopct='%1.1f%%', colors=couleurs)
    plt.title('Distribution des Protocoles Reseau')
    plt.savefig(nom_fichier, dpi=100, bbox_inches='tight')
    plt.close()
    print(f"OK ! Image créée : {nom_fichier}")


def creer_rapport_markdown(donnees, resultats, problemes, nom_fichier):
    """Crée le rapport au format Markdown"""
    print("Création du rapport Markdown...")
    
    f = open(nom_fichier, 'w', encoding='utf-8')
    
    # En-tête
    f.write("# Rapport d'Analyse Reseau - SAE 1.05\n\n")
    f.write("**BUT Reseaux & Telecommunications**\n\n")
    f.write("---\n\n")
    
    # Résumé
    f.write("## Resume\n\n")
    if len(problemes) > 0:
        f.write("⚠️ **" + str(len(problemes)) + " anomalie(s) detectee(s) !**\n\n")
    else:
        f.write("✅ Aucune anomalie\n\n")
    
    # Statistiques
    volume_total = 0
    for ip in resultats['octets_par_ip']:
        volume_total = volume_total + resultats['octets_par_ip'][ip]
    
    f.write("## Statistiques Generales\n\n")
    f.write("- Total de paquets : " + str(resultats['total']) + "\n")
    f.write("- Volume total : " + str(round(volume_total/1024, 2)) + " Ko\n")
    f.write("- IP sources : " + str(len(resultats['paquets_par_ip'])) + "\n")
    f.write("- Protocoles : " + str(len(resultats['paquets_par_protocole'])) + "\n\n")
    
    # Images
    f.write("## Images d'Analyse\n\n")
    f.write("![Anomalies](anomalies.png)\n\n")
    f.write("![Trafic](analyse_trafic.png)\n\n")
    f.write("![Protocoles](protocoles.png)\n\n")
    
    # Top 10 IP
    f.write("## Top 10 IP Sources\n\n")
    f.write("| Rang | IP | Paquets | % | Ko |\n")
    f.write("|------|----|---------|----|----|\\n")
    
    liste_ip = []
    for ip in resultats['paquets_par_ip']:
        liste_ip.append((ip, resultats['paquets_par_ip'][ip]))
    liste_ip.sort(key=lambda x: x[1], reverse=True)
    
    for i in range(min(10, len(liste_ip))):
        ip = liste_ip[i][0]
        nb = liste_ip[i][1]
        pourcent = (nb * 100) / resultats['total']
        
        ko = 0
        if ip in resultats['octets_par_ip']:
            ko = resultats['octets_par_ip'][ip] / 1024
        
        f.write("| " + str(i+1) + " | " + ip + " | " + str(nb) + " | ")
        f.write(str(round(pourcent, 1)) + "% | " + str(round(ko, 2)) + " |\n")
    
    f.write("\n")
    
    # Protocoles
    f.write("## Protocoles\n\n")
    f.write("| Protocole | Paquets |\n")
    f.write("|-----------|--------|\n")
    
    for proto in resultats['paquets_par_protocole']:
        f.write("| " + proto + " | " + str(resultats['paquets_par_protocole'][proto]) + " |\n")
    
    f.write("\n")
    
    # Anomalies
    if len(problemes) > 0:
        f.write("## ⚠️ Anomalies Detectees\n\n")
        f.write("| Type | IP | Gravite | Nombre |\n")
        f.write("|------|----|---------|--------|\n")
        
        for pb in problemes:
            f.write("| " + pb['type'] + " | " + pb['ip'] + " | ")
            f.write(pb['gravite'] + " | " + str(pb['nombre']) + " |\n")
        
        f.write("\n")
    
    # Conclusion
    f.write("## Conclusion\n\n")
    if len(problemes) > 0:
        f.write("Des anomalies ont ete detectees. Mesures de securite necessaires.\n\n")
    else:
        f.write("Trafic normal. Pas d'anomalie.\n\n")
    
    f.write("---\n")
    f.write("*Rapport genere automatiquement*\n")
    
    f.close()
    print(f"OK ! Rapport créé : {nom_fichier}")


def traiter_csv(chemin):
    """Fonction principale qui orchestre l'analyse"""
    print("\n========== DEBUT ==========\n")
    
    # Créer le dossier de résultats
    if not os.path.exists('resultats_interface'):
        os.makedirs('resultats_interface')
    
    # Étapes de traitement
    donnees = lire_fichier_csv(chemin)
    resultats = analyser_donnees(donnees)
    problemes = detecter_problemes(resultats)
    
    # Génération des fichiers
    creer_image_anomalies(problemes, 'resultats_interface/anomalies.png')
    creer_image_trafic(resultats, problemes, 'resultats_interface/analyse_trafic.png')
    creer_image_protocoles(resultats, 'resultats_interface/protocoles.png')
    creer_rapport_markdown(donnees, resultats, problemes, 'resultats_interface/rapport.md')
    
    print("\n========== TERMINE ==========\n")
    
    # Message de confirmation
    message = "Analyse terminee !\n\n"
    message = message + "Paquets analyses : " + str(len(donnees)) + "\n"
    message = message + "Anomalies trouvees : " + str(len(problemes)) + "\n\n"
    message = message + "Fichiers crees :\n- rapport.md\n- 3 images PNG"
    
    messagebox.showinfo("Termine !", message)


def bouton_choisir():
    """Ouvre la boîte de dialogue pour choisir le CSV"""
    fichier = filedialog.askopenfilename(
        title="Choisir le fichier CSV",
        filetypes=[("Fichiers CSV", "*.csv"), ("Tous les fichiers", "*.*")]
    )
    
    if fichier:
        traiter_csv(fichier)


# Interface graphique
fenetre = tk.Tk()
fenetre.title("Analyseur Reseau")
fenetre.geometry("450x250")

label_titre = tk.Label(
    fenetre,
    text="Analyseur de Trafic Reseau",
    font=("Arial", 14, "bold")
)
label_titre.pack(pady=20)

label_description = tk.Label(
    fenetre,
    text="Ce programme genere 3 images :\n- Les anomalies detectees\n- L'analyse du trafic\n- La distribution des protocoles",
    font=("Arial", 10)
)
label_description.pack(pady=15)

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

bouton_quitter = tk.Button(
    fenetre,
    text="Quitter",
    command=fenetre.quit,
    bg="#e74c3c",
    fg="white",
    font=("Arial", 10),
    padx=20,
    pady=5
)
bouton_quitter.pack(pady=10)

fenetre.mainloop()
