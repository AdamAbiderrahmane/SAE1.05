# SAE1.05 Network Traffic Analysis Tool

## 📋 Prerequisites

### Required Python Version
- Python 3.8 or higher

### Required Libraries
```
tkinter          # Graphical interface (included with Python)
matplotlib       # Graph creation
```
### library installation 
`pip install matplotlib` 

Optional Software
Microsoft Excel (for manual data analysis)


## 🎯 What This Project Does

This tool helps you find out why a network is having problems. It reads network traffic files (tcpdump format) and tells you if something suspicious is happening - like attacks, port scans, or unusual behavior.
I built this for my university project at IUT Roanne. The idea was simple: our company has two sites (one in France, one in India), and the network in India was having issues. Normal checks didn't work, so I created these Python programs to dig deeper into the traffic data.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 📦 What's Inside

The project has two main Python scripts:

**Extraction_TXT_A_CSV :** TXT to CSV Converter
Takes your raw tcpdump file and converts it into a clean spreadsheet format that's easy to read.

**Extraction_CSV_A_MARKDOWN :** CSV Analyzer convert in Markdown
Reads the spreadsheet, analyzes everything, and creates a report with graphs showing what's going on.
Excel File
You can also open the CSV file in Excel to explore the data yourself.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## ⚙️ How It Works

**Extraction_TXT_A_CSV Explained**
The first script opens a window on your screen. You click a button, choose your tcpdump text file, and it extracts all the important information:
-	When each packet was sent (timestamp)
-	What protocol was used (IP, TCP, etc.)
-	Where it came from (source IP and port)
-	Where it was going (destination IP and port)
-	Special flags (like SYN, ACK)
-	Packet sizes and sequence numbers
Then it saves everything into a CSV file with columns separated by semicolons. Super simple.
<img width="1488" height="866" alt="image" src="https://github.com/user-attachments/assets/efa82753-d930-4b54-af1e-28967bde477d" />

---------------------------------------------------------------------------------------------
## Extraction_CSV_A_MARKDOWN Explained
The second script reads your CSV file and does the detective work. It looks for three main problems :

## 🟥 Detection Thresholds

| Attack Type | Description | Threshold |
|------------|-------------|-----------|
| **SYN Flood Attack** | When one computer sends too many connection requests | `> 100 SYN packets` |
| **Port Scanning** | When someone is checking more than 50 different ports on your network | `> 50 different ports` |
| **Traffic Flooding** | When one IP address is responsible for more than 40% of all your network traffic | `> 40% of total traffic` |

After analyzing, it creates a folder called `resultats_interface/` with:
- A Markdown report with all the statistics
- 3 PNG images showing graphs and charts
- Clear lists of any problems it found

## 📊 What You Get

When you run both scripts, here's what gets created:
CSV File - All your network packets in a neat table format
Markdown Report - A text document with:
- How many packets were analyzed
- Total data volume
- Top 10 most active IP addresses
- What protocols were used
- Any suspicious activity found
<img width="1486" height="871" alt="image" src="https://github.com/user-attachments/assets/c508e4cd-8ab3-462e-96fd-6b1d53b1e416" />

## 🖼️ Three Images

| Image File | Description |
|------------|-------------|
| **anomalies.png** | Shows all the problems detected with severity levels |
<img width="706" height="607" alt="image" src="https://github.com/user-attachments/assets/7cee89f6-f6bd-40f4-a487-693502770744" />

| **analyse_trafic.png** | Four graphs showing traffic patterns, attack peaks, top IPs, and data volumes |
<img width="516" height="613" alt="image" src="https://github.com/user-attachments/assets/2172afcb-1c31-44b2-bd06-05336bb651d2" />

| **protocoles.png** | A pie chart of which protocols are being used |
<img width="597" height="617" alt="image" src="https://github.com/user-attachments/assets/400be61b-8e3c-4938-b6dd-0f4c562e81bc" />

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 🚀 How to Use This

Installation
First, install matplotlib if you don't have it:

```
pip install matplotlib
```

Then clone the project:

```
git clone https://github.com/AdamAbiderrahmane/SAE1.05.git
cd SAE1.05
```

## 🧗Step-by-Step Usage

👍Step 1: Convert your tcpdump file
Run the first script:

```
python Extraction_TXT_A_CSV.py
```

```
Démarrage de la conversion...
Lecture : (tcpdump file.txt)
Lignes lues : 507891
Paquets extraits : 11016
Lignes ignorées : 496875
Fichier créé : (name of the file)
```

A window pops up. Click "Choisir un fichier" (Choose file), select your tcpdump text file for example you have `DumpFile.txt` in my repository, then choose where to save the CSV. The program will tell you how many packets it found.

👍Step 2: Analyze the data
Run the second script:

```
python Extraction_CSV_A_MARKDOWN.py
```

```
========== DEBUT ==========

J'ai lu 11016 paquets
Analyse en cours...
Analyse terminée !
Je cherche les anomalies...
J'ai trouvé 2 problème(s)
Création de l'image des anomalies...
OK ! Image créée : resultats_interface/anomalies.png
Création de l'image du trafic...
OK ! Image créée : resultats_interface/analyse_trafic.png
Création de l'image des protocoles...
OK ! Image créée : resultats_interface/protocoles.png
Création du rapport Markdown...
OK ! Rapport créé : resultats_interface/rapport.md

========== TERMINE ==========
```

👍Step 3: Check the results
Open the `resultats_interface/` folder. You'll see:
```
resultats_interface/
├── rapport.md              # Read this first. It tells you everything.
├── anomalies.png          # Visual alert of detected problems
├── analyse_trafic.png     # Four comprehensive traffic graphs
└── protocoles.png         # Protocol distribution pie chart
└── rapport.md        # file report
```
- rapport.md - Read this first. It tells you everything.
- The three PNG images - Look at these to see the graphs.
- If there are problems, they'll be clearly listed with red or orange warnings.
<img width="372" height="142" alt="image" src="https://github.com/user-attachments/assets/4b97c530-c4a3-414a-9ea1-7a002153d2ae" />

##🔍 Understanding the Results

If No Problems Found
The anomalies image will say "Aucune anomalie detectee" (No anomalies detected) in green. Your network traffic looks normal.
If Problems Found
You'll see alerts like:

```
⚠️ SYN FLOOD from IP 192.168.1.50 - High severity - 250 packets
⚠️ PORT SCAN from IP 10.0.0.15 - Medium severity - 75 ports
```
<img width="1918" height="962" alt="image" src="https://github.com/user-attachments/assets/db2eb94d-55c0-4d83-808a-c86e1cdc8a74" />

The graphs show you:

## 🔍 Understanding the Results

The graphs show you:

| 📊 Graph Section | 📈 What It Shows |
|--------------|---------------|
| **Attack peaks by hour** | When the problems happened |
| **Top 5 IPs** | Which computers are sending the most traffic (suspicious ones are in red) |
| **Data volumes** | How much data each IP is sending |
| **Protocol distribution** | What types of traffic you have |


## ❗ Common Problems and Fixes
| 🔴 Problem | ✅ Solution |
|---------|----------|
| Script says **"No data found"** | Make sure your text file is actually from tcpdump and has lines with "IP" in them |
| CSV won't open properly | When opening in Excel, choose **semicolon (;)** as the separator, not comma |
| `ModuleNotFoundError: matplotlib` | Run `pip install matplotlib` in your terminal |
| Images don't show up | Check if the `resultats_interface/` folder was created. If not, the script might have had an error |
| Window doesn't open | Make sure tkinter is installed (it usually comes with Python automatically) |


## 📁 File Structure
```
SAE1.05/
├── Extraction_TXT_A_CSV.py        # First script: TXT to CSV
├── Extraction_CSV_A_MARKDOWN.py   # Second script: Analysis
├── resultats_interface/           # Output folder (created automatically)
│   ├── rapport.md                 # Your main report
│   ├── anomalies.png              # Problems detected
│   ├── analyse_trafic.png         # Four traffic graphs
│   └── protocoles.png             # Protocol pie chart
├── fichier1000.txt                # Example tcpdump file
├── fichier182.txt                 # Another example
└── README.md                      # This file
```

## 🔧 Technical Details
CSV Format
The CSV uses semicolons as separators with these columns:
```
Timestamp;Protocole;IP Source;Port Source;IP Destination;Port Destination;Flags;Seq;Ack;Window;Length
```
Example line :
```
11:42:04.766656;IP;BP-Linux8;22;192.168.190.130;50019;P.;2243505564;1972915080;312;108
```

## 🚥 Detection Thresholds
### Detection Thresholds
### 🚨 Detection Thresholds

| Anomaly Type | Trigger Condition | Threshold Value |
|-------------|-------------------|-----------------|
| 🔴 **SYN Flood** | Triggers when one IP sends over 100 SYN packets | `> 100 SYN packets` |
| 🟠 **Port Scan** | Triggers when one IP contacts over 50 different ports | `> 50 different ports` |
| 🟡 **Flood** | Triggers when one IP generates over 40% of total traffic | `> 40% of total traffic` |

Main Functions in `Extraction_TXT_A_CSV.py` 
### Main Functions in `Extraction_TXT_A_CSV.py`

#### 🔧 Core Functions

| Function | Description |
|----------|-------------|
| `trouver_ip_et_port(texte)` | Separates IP addresses from port numbers |
| `chercher_valeur(liste_mots, mot_a_chercher)` | Finds specific values in packet data |
| `extraire_flags(ligne_complete)` | Pulls out TCP flags from packet data |
| `analyser_ligne(ligne)` | Parses each tcpdump line |
| `convertir_fichier(fichier_entree, fichier_sortie)` | Main conversion function |

#### 🎛️ GUI Functions

| Function | Description |
|----------|-------------|
| `bouton_choisir()` | Choose file button handler |
| `bouton_quitter()` | Exit button handler |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Main Functions in `Extraction_CSV_A_MARKDOWN.py`
### 📊 Main Functions in `Extraction_CSV_A_MARKDOWN.py`

#### 📥 Data Processing

| Function | Description |
|----------|-------------|
| `lire_fichier_csv(nom_fichier)` | Loads the CSV data |
| `analyser_donnees(donnees)` | Counts packets, bytes, ports per IP |
| `detecter_problemes(resultats)` | Checks for anomalies using thresholds |

#### 📈 Visualization & Reporting

| Function | Description |
|----------|-------------|
| `creer_image_anomalies(problemes, nom_fichier)` | Makes the anomaly alert image |
| `creer_image_trafic(resultats, problemes, nom_fichier)` | Creates the four-graph analysis |
| `creer_image_protocoles(resultats, nom_fichier)` | Makes the protocol pie chart |
| `creer_rapport_markdown(donnees, resultats, problemes, nom_fichier)` | Writes the full report |

#### 🎛️ GUI Functions

| Function | Description |
|----------|-------------|
| `bouton_choisir()` | Choose file button handler |
| `bouton_quitter()` | Exit button handler |

## 💡 Why This Matters
Network problems can be hard to spot. Sometimes you have thousands or millions of packets to look through. These tools do the boring work for you - they read all the data, find patterns, and highlight anything weird.
For our scenario, the Indian production site was having network issues. Using these tools, we can quickly see if it's:

#### 🔴 A security attack (someone flooding or scanning the network)
#### 🟠 A configuration problem (one computer sending too much)
#### 🟢 Normal traffic that just needs more bandwidth

## 👨‍🎓 About This Project
This was made for SAE 1.05 (Data Processing) in my first year of BUT Networks and Telecommunications at IUT Roanne. The goal was to learn Python, understand network analysis, and create practical tools that real IT teams could use.
The instructions said our tool needed to work for teams in India who speak English, so everything needed to be clear and simple to understand.

## 📊 Excel Analysis

### How to Use Excel

You can open the CSV file in Excel for manual analysis.

#### Import Steps

1. Open Excel → **Data** → **From Text/CSV**
2. Select your CSV file
   <img width="945" height="501" alt="image" src="https://github.com/user-attachments/assets/b3cdfabf-48b7-47f9-bb1b-a90b317f0aea" />
   <img width="945" height="502" alt="image" src="https://github.com/user-attachments/assets/33a8e296-d151-46f8-a298-37bb8368cc01" />

4. **Important:** Choose **semicolon (;)** as delimiter
5. Click **Load**
<img width="945" height="501" alt="image" src="https://github.com/user-attachments/assets/2b2cec45-c868-4db0-9217-27219d7589d3" />

#### Enable VBA Macro (Optional)

- Press `Alt + F11` to open VBA editor
<img width="945" height="496" alt="image" src="https://github.com/user-attachments/assets/6bf32815-0703-4e69-88c8-d39641ea60e4" />

- Press `Alt + F8` to run the analysis macro
<img width="945" height="499" alt="image" src="https://github.com/user-attachments/assets/577d28fa-c40c-44c9-ad98-e125b4b5ec00" />

- Execute the macro for automated formatting
<img width="945" height="493" alt="image" src="https://github.com/user-attachments/assets/af5c0919-eaa2-4855-8556-45699d5a3040" />

#### What You Can Do

- 🔍 **Filter** data by IP address or protocol
- 🔢 **Calculate totals** for specific IPs

## 📫 Contact
**Author:** Adam Abiderrahmane
**Program:** BUT Réseaux et Télécommunications - Year 1
**School:** IUT Roanne
**Project:** SAE 1.05 - Data Processing

GitHub: @AdamAbiderrahmane
