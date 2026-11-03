# Wi-Fi Accès

Logiciel **open source** (licence [MIT](LICENSE)) pour Linux.

Ton cousin a donné le code Wi-Fi aux voisins, le réseau est lent : cet outil montre **qui est connecté**. Tu peux **nommer** un appareil, **bloquer** (ça ouvre la box avec l’adresse MAC), ou **virer tout le monde** en changeant le mot de passe Wi-Fi.

Ça marche chez toi **et chez maman** : clone le même dépôt, installe, scanne, change le mot de passe.

## Installer en clonant le dépôt

Sur l’ordinateur Linux (chez toi ou chez maman) :

```bash
git clone https://github.com/RicardoKOUKOUI/wifi-acces.git
cd wifi-acces
chmod +x install-linux.sh
./install-linux.sh
```

Ensuite cherche **Wi-Fi Accès** dans le menu, ou tape :

```bash
wifi-acces
```

Si la commande n’est pas trouvée, ferme le terminal, rouvre-le, ou lance :

```bash
python3 wifi_acces.py
```

Si ça ne s’ouvre pas :

```bash
sudo apt update
sudo apt install python3 python3-gi gir1.2-gtk-3.0 network-manager git
```

Puis relance `./install-linux.sh`.

### Fedora

```bash
sudo dnf install python3 python3-gobject gtk3 NetworkManager git
```

## Comment l’utiliser

1. Clique **Scanner le Wi-Fi** — ça parcourt **tout** le réseau, pas seulement ton sous-réseau
2. Tu vois les appareils : **TOI**, **BOX**, et les **INCONNUS**, avec type (téléphone, PC, TV…), marque et système
3. **Nommer** : ex. « téléphone de maman »
4. **Bloquer** : copie l’adresse MAC et ouvre la box pour le mettre en liste noire
5. **Virer tout le monde** : ouvre la box, change le **mot de passe Wi-Fi**, donne le nouveau code seulement à la famille

C’est le changement de mot de passe qui coupe vraiment les voisins. Tant qu’ils ont l’ancien code, ils peuvent revenir.

## Lancer sans installer

```bash
git clone https://github.com/RicardoKOUKOUI/wifi-acces.git
cd wifi-acces
python3 wifi_acces.py
```

## Contribuer

Issues et pull requests bienvenues.
