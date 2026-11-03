# Wi-Fi Accès

Logiciel **open source** pour Linux. Il liste les appareils connectés à ton Wi-Fi, te laisse leur donner un nom, et ouvre la page de ta box pour changer le mot de passe.

Licence : [MIT](LICENSE)

## Installer en clonant le dépôt

Sur Linux (Debian, Ubuntu, Parrot, Linux Mint, Fedora, etc.) :

```bash
git clone https://github.com/RicardoKOUKOUI/wifi-acces.git
cd wifi-acces
chmod +x install-linux.sh
./install-linux.sh
```

Ensuite cherche **Wi-Fi Accès** dans le menu des applications, ou lance :

```bash
wifi-acces
```

### Dépendances

Si l’appli ne s’ouvre pas, installe GTK et Python :

```bash
sudo apt update
sudo apt install python3 python3-gi gir1.2-gtk-3.0 network-manager
```

Sur Fedora :

```bash
sudo dnf install python3 python3-gobject gtk3 NetworkManager
```

## Utilisation

1. Clique **Scanner le Wi-Fi**
2. Les appareils inconnus sont marqués **INCONNU** — tu peux les nommer
3. Clique **Ouvrir la box** pour changer le mot de passe Wi-Fi (c’est ça qui coupe vraiment les gens en trop)

Sur un Wi-Fi d’opérateur ou d’immeuble, tu peux aussi voir des appareils qui ne sont pas chez toi.

## Lancer sans installer

```bash
git clone https://github.com/RicardoKOUKOUI/wifi-acces.git
cd wifi-acces
python3 wifi_acces.py
```

## Contribuer

Les issues et pull requests sont les bienvenues.
