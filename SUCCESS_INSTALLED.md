# ✅ SUCCÈS! L'Application est Installée!

## 🎉 Ce qui est fait

✅ **APK signé correctement** (tous les splits)  
✅ **Application installée** sur votre téléphone  
✅ **Script SSL unpinning** transféré  
✅ **Frida Gadget** intégré dans l'app  

---

## 📱 Prochaines Étapes

### 1. Installer Frida et mitmproxy sur votre PC

```bash
py -m pip install frida-tools mitmproxy
```

### 2. Trouver l'IP de votre PC

```bash
ipconfig
```

Cherchez "Adresse IPv4" (exemple: `192.168.1.100`)

### 3. Configurer le Proxy WiFi sur votre Téléphone

1. **Paramètres** → **WiFi**
2. **Appui long** sur votre réseau
3. **Modifier le réseau**
4. **Options avancées**
5. **Proxy:** Manuel
6. **Nom d'hôte:** `<IP de votre PC>` (de l'étape 2)
7. **Port:** `8080`
8. **Enregistrer**

### 4. Démarrer mitmproxy sur votre PC

```bash
mitmweb -p 8080
```

Cela ouvrira un navigateur à: `http://localhost:8081`

### 5. Installer le Certificat mitmproxy sur votre Téléphone

1. Sur le navigateur de votre téléphone, allez à: **`http://mitm.it`**
2. Appuyez sur **Android**
3. Téléchargez le certificat
4. **Paramètres** → **Sécurité** → **Installer depuis le stockage**
5. Sélectionnez le certificat téléchargé
6. Donnez-lui un nom: **"mitmproxy"**
7. OK!

### 6. Lancer MaynDrive et Frida

**Sur votre téléphone:**
- Ouvrez l'app **MaynDrive**

**Sur votre PC:**
```bash
frida -U Gadget -l ssl-unpinning.js
```

Vous devriez voir:
```
[*] Frida script loaded
[+] SSL Unpinning active
```

### 7. Capturer le Trafic!

1. **Sur téléphone:** Utilisez MaynDrive (login, voir les scooters, etc.)
2. **Sur PC navigateur:** Regardez le trafic à `http://localhost:8081`
3. **Vous verrez toutes les requêtes API en temps réel!**

### 8. Exporter et Analyser

Dans le navigateur mitmweb:
1. **File** → **Export** → **Save**
2. Sauvegarder comme: `captured.har`

Puis analysez:
```bash
py traffic_analyzer.py captured.har
```

---

## 🎯 Ce que vous allez voir

```http
POST https://api.knotcity.io/api/application/login
Authorization: Bearer eyJhbGc...
X-Device-ID: abc123...

{
  "email": "votre@email.com",
  "password": "votre_mot_de_passe",
  "device": {...},
  "scope": "user"  ← Testez "admin" ici!
}
```

---

## ⚠️ Dépannage

### Frida ne trouve pas "Gadget"

```bash
# Lister tous les processus
frida-ps -U

# Cherchez le nom du processus MaynDrive et utilisez-le:
frida -U -n "fr.mayndrive.app" -l ssl-unpinning.js
```

### Pas de trafic dans mitmproxy

1. Vérifiez que le proxy est configuré sur le téléphone
2. Visitez `http://mitm.it` sur le téléphone (devrait charger)
3. Assurez-vous que le script Frida tourne sans erreurs
4. Redémarrez l'app MaynDrive

### Erreur de certificat

1. Assurez-vous d'avoir installé le cert depuis `http://mitm.it`
2. Installez comme "certificat CA" pas "VPN"
3. Vous devrez peut-être définir un verrouillage d'écran (PIN) d'abord

---

## 📊 Résumé Rapide

```bash
# 1. Installer les outils
py -m pip install frida-tools mitmproxy

# 2. Configurer proxy WiFi sur téléphone
#    Hostname: <IP de votre PC>
#    Port: 8080

# 3. Démarrer mitmproxy
mitmweb -p 8080

# 4. Installer cert: http://mitm.it sur téléphone

# 5. Lancer app + Frida
frida -U Gadget -l ssl-unpinning.js

# 6. Utiliser MaynDrive et capturer!

# 7. Analyser
py traffic_analyzer.py captured.har
```

---

## 🎓 Mise à Jour de l'API

Une fois le trafic capturé, vous découvrirez:
- ✅ Les vrais endpoints API
- ✅ Les en-têtes requis (clés API, IDs d'appareil)
- ✅ Les formats de requête/réponse
- ✅ Si l'escalade de scope fonctionne

Puis mettez à jour `mayn_drive_api.py` avec les vraies données et relancez la démo d'exploit!

---

## ✅ Tout est Prêt!

L'app MaynDrive avec Frida Gadget est maintenant installée sur votre téléphone.

**Suivez simplement les étapes ci-dessus pour capturer le trafic!** 🚀📱🔍

