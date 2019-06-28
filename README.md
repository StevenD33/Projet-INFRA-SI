# Projet INFRA


* [I. Introduction ](#i-Introduction)
* [II. SOC](#ii-SOC)
* [III. IDS et NIDS](#iii-IDS-et-NIDS)
* [IV. Suricata](#iv-Suricata)
* [V. Installation Pfsense](#v-Installation-Pfsense)
* [VI. Installation Suricata](#vi-Installation-Suricata)
* [VII. Ajout de Regles sur Suricata](#vii-Ajout-de-Regles-sur-Suricata)

# I. Introduction

Aujourd'hui Internet se développe à une vitesse impressionnante.  

C'est le 5e Espace de combat pour l’OTAN  de ce fait des moyen de cyberdéfense et d'attaque sont mis en place  (Guerre numérique/ Cyberguerre )

Le système d'information (SI) est un ensemble organisé de ressources qui permet de collecter, stocker, traiter et distribuer de l'information
Qu’est ce qui compose les SI :
- L’infrastructure – serveurs, stockage, bases de données, réseaux, v*
- Les applications – le SIRH (Système d'Information des Ressources Humaines), le marketing, les verticaux métiers, les développements spécifiques, les services, 
-  les API (Application Programming Interface), etc.
- Les utilisateurs – plus précisément les outils et services du poste de travail 
- L’administration – la gestion du SI et de ses composants

Il y'a de plus en plus de SI et de ce fait il y'a de plus en plus de donnée ce qui augmente la convoitise et le risque d'attaque 

Vulnérabilité + menace = risque

Pour cela il existe la sécurité informatique qui fonctionne sur plusieurs dimensions :
- La Protection
- La Détection 
- La Résilience  
Les objectifs de la Sécurité informatique peuvent être : 
 - Garantir l’intégrité (garantir que les données que l’on a sont bien celle que l’on croit) des données
- La confidentialité : être sur que seul les personnes autorisé aient accès aux données confidentielle ou aux échanges de ressources
- La disponibilité : Assure un bon fonctionnement
- La non-répudiation : la possibilité de vérifier que l'envoyeur et le destinataire sont bien les parties qui disent avoir respectivement envoyé ou reçu le message.

# II. SOC 

Un SOC Security Operation Center (Centre opérationnel de sécurité) sert à superviser les SI

Afin de se protéger des cyber attaques et d’avoir des moyens de réponse et d’action en cas d’intrusion
Exemple de Méthode de fonctionnement d'un SOC : 
- Détection
	- Collecte et analyse des logs
	- Corrélation des informations afin d’analyser les évènements de sécurité dans leur ensemble et pas unitairement
	- Déclenchement et qualification d’alerte sur éléments suspects

- Réaction
	- Réduction du délai de réaction pendant toutes les phases d’une attaque (préparation, en cours, et après)
	- Traitement immédiat des alertes documentées, et escalade d’alertes vers les analystes pour des cas non connus
	- Traitement des incidents de sécurité en accompagnement des équipes de supervision
	- Investigations suite à incident de sécurité
- Prévention
	 - Maintien en Condition Opérationnelle (MCO) de l’outillage SOC
	 - Maintien en Condition de Sécurité (MCS) de l’outillage SOC
	 - Optimisation des règles de détection, et prise en compte des Indicators of Compromise (IoC) fournis par les CSIRT/CERT

- Communication et Reporting
	- Reporting régulier de l’activité du SOC
	- Tableau de bord Sécurité au travers d’indicateurs de service (Alertes, Incidents, Investigations, …), d’indicateurs techniques (MCO/MCS), et d’indicateurs d’évolution (extension du périmètre de collecte, nouvelles règles de détection, …)

Le SOC représente un environnement de travail à lui tout seul et représente un investissement, tous le monde ne peut pas investir dedans. 

# III. IDS et NIDS 


Un Intrusion Detection System c'est un système qui permet de repérer des activités anormales ou suspectes sur une cible analysé par exemple un réseau ou un hôte 
Il exite plusieurs types d'IDS par exemple : 
 - les NIDS (Network Intrusion Detection System), qui surveillent l'état de la sécurité au niveau du réseau
- les HIDS (Host Intrusion Detection System), qui surveillent l'état de la sécurité au niveau des hôtes
- les IDS hybrides, qui utilisent les NIDS et HIDS pour avoir des alertes plus pertinentes.
![Nids.png](https://upload.wikimedia.org/wikipedia/commons/6/60/Nids.png)

### Approche par scénario 
La capture sert à la récupération de trafic réseau. En général cela se fait en temps réel, bien que certains NIDS permettent l'analyse de trafic capturé précédemment.

La plupart des NIDS utilisent la bibliothèque standard de capture de paquets libpcap.  Son mode de fonctionnement est de copier (sous Linux) tout paquet arrivant au niveau de la couche liaison de données Une fois ce paquet copié, il lui est appliqué un filtre BPF (Berkeley Packet  Filter), correspondant à l'affinage de ce que l'IDS cherche à récupérer comme information.


Il se peut que certains paquets soient ignorés car sous une forte charge, le système d'exploitation ne les copiera pas.

Les bibliothèques de signatures (approche par scénario) rendent la démarche d'analyse similaire à celle des antivirus quand ceux-ci s'appuient sur des signatures d'attaques. Ainsi, le NIDS est efficace s'il connaît l'attaque, mais inefficace dans le cas contraire. Les outils à base de signatures requièrent des mises à jour très régulières.

Les NIDS ont pour avantage d'être des systèmes temps réel et ont la possibilité de découvrir des attaques ciblant plusieurs machines à la fois. Leurs inconvénients sont le taux élevé de faux positifs qu'ils génèrent, le fait que les signatures aient toujours du retard sur les attaques de type 0day et qu'ils puissent être la cible d'une attaque.

# IV. Suricata 

Suricata est un framework de détection gratuit et open source de menace réseau il est capable de faire de L'IDS de l'IPS et du Network security Monitoring 

C'est un projet qui est supporté par L'Open Information Security Foundation (OISF) qui est une fondation à but non lucrative 


# V. Installation Pfsense 

### 1. Téléchargement de l'iso 

Pour commencer il faut télécharger l'iso pfsense sur le site de pfsense [https://www.pfsense.org/download/?section=downloads](https://www.pfsense.org/download/?section=downloads)

Pour notre cas on va choisir l'architecture amd64 car on veut l'installer sur une VM. 

### 2. Créer une VM

L'installation sur une VM c'est la meme chose que l'installation sur une machine physique 

En terme de configuration requise,
Vm avec 2Go de RAM et 8go de disque  Même si on peut faire avec moins mais pour Suricata il faut quand même un minimum de RAM 

On oublie pas de séléctionner l'iso pour que ça boot tout seul sur Pfsense. 

### 3. Installation 

Lors de son installation on sélectionne les options par défaut on les modifiera si besoin plus tard 

Lors du premier démarrage de Pfsense, il faut configurer les différentes interfaces (WAN, LAN, DMZ, etc.), il faut donc bien repérer vos différentes cartes réseaux afin de ne pas vous tromper dans votre configuration auquel cas vous n'aurez pas accès à l'interface web et votre pare-feu ne fonctionnera pas. (C'est du vécu) 

Ensuite Pfsense va nous demander si on veut mettre en place un Vlan la réponse est non pour le début on le fera à la main plus tard si nécessaire.

### 4. FIN 

Pfsense ensuite va nous afficher un menu avec une ip pour accéder au webconfigurateur et il faudra ensuite configurer le firewall et le NAT pour faire du routage mais cela dépend de chaque personne et de chaque configuration 

Dans mon cas j'ai configure le 192.168.60.0 en tant que réseau WAN et le 192.168.1.0 en tant que LAN. 

# VI. Installation Suricata 

### CLI 

Installation des dépendances pour compiler le paquet 

	pkg install libtool autoconf automake pkgconf pcre libyaml libnet

Edit /etc/rc.conf et modifier les lignes suivantes : 

	firewall_enable="YES" 
	firewall_type="open"

Edit /boot/loader.conf et modifiier les lignes suivantes : 

	ipfw_load="YES" 
	ipfw_nat_load="YES" 
	ipdivert_load="YES" 
	dummynet_load="YES" 
	libalias_load="YES"

Télécharger Suricata : 

	wget http://www.openinfosecfoundation.org/download/suricata-3.1.tar.gz
	tar -xvzf suricata-3.1.tar.gz
	cd suricata-3.1

Taper les commandes suivantes : 

	./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
	make
	make install
	zerocopy bpf
	mkdir /var/log/suricata/
On peut aussi utiliser la commande :

	./configure && make && make install-full
Qui permet d'installer tous et de préparer suricata il ne restera plus qu'a le lancer 

### Basic Setup 

Préparer le systeme pour l'utilisation :

	sudo mkdir /etc/suricata

Il faut ensuite copier des fichier de suricata dans /etc/suricata 

	sudo cp classification.config /etc/suricata
	sudo cp reference.config /etc/suricata
	sudo cp suricata.yaml /etc/suricata

La commande 

	./configure && make && make install-full
Le fait tout seul. 


### Installation depuis le webconfigurateur

Pour l'installation depuis le webconfigurateur il faut aller dans le gestionnaire de paquet et rechercher le paquet suricata puis l'installer. 

Ensuite dans le dashboard apparait le module suricata on clique dessus et on peut ensuite configurer les interfaces avec les regles à y ajouter etc etc pour plus d'information voici une vidéo bien faite sur le sujet 
[Link](https://www.youtube.com/watch?v=KRlbkG9Bh6I)


# VII. Ajout de Regles sur Suricata

Le plus simple pour ajouter une regle c'est de le faire depuis le webconfigurateur pour cela il faut 
Aller dans Service > Suricata 

![1](https://github.com/StevenDias33/Projet-INFRA-SI/blob/master/Ressources/1.png)

On choisis l'interface que l'on veut modifier 

![2](https://github.com/StevenDias33/Projet-INFRA-SI/blob/master/Ressources/2.png)

Ensuite on va dans LAN RULES 

![3](https://github.com/StevenDias33/Projet-INFRA-SI/blob/master/Ressources/3.png)

Pour ajouter des regles il faut aller dans custom rules qui se trouve dans Available Categories 

![4](https://github.com/StevenDias33/Projet-INFRA-SI/blob/master/Ressources/4.png)

Ensuite on Ajoute les règles que l'on souhaite par exemple ici j'ai ajouter ces règles 

	alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sS window 2048"; fragbits:!D; dsize:0; flags:S,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000537; classtype:attempted-recon; sid:2000537; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

	alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sO"; dsize:0; ip_proto:21; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000536; classtype:attempted-recon; sid:2000536; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

	alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sA (1)"; fragbits:!D; dsize:0; flags:A,12; window:1024; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000538; classtype:attempted-recon; sid:2000538; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

	alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sA (2)"; fragbits:!D; dsize:0; flags:A,12; window:3072; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000540; classtype:attempted-recon; sid:2000540; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

	alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -f -sF"; fragbits:!M; dsize:0; flags:F,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000543; classtype:attempted-recon; sid:2000543; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
	
	alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -f -sN"; fragbits:!M; dsize:0; flags:0,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000544; classtype:attempted-recon; sid:2000544; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
	
	alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -f -sX"; fragbits:!M; dsize:0; flags:FPU,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000546; classtype:attempted-recon; sid:2000546; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

On sauvegarde et on relance l'interface et c'est ok, 


Ce projet était super cool malgrés le peu de temps que j'ai eu pour le faire et je vais vraiment essayer d'aller beaucoup plus loin l'année prochaine la dessus car le coté Blue team en sécu est super intéréssant. 

Merci D'avoir lu ce rendu un peu fait à l'arrache 
