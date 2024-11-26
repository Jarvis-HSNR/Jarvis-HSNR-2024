from cryptography.fernet import Fernet
import hashlib
import base64

class DateiVerschluesseler:
    def __init__(self):
        pass

    def schluesselErzeugen(self, schluessel):
        gehashter_schluessel = hashlib.sha256(schluessel.encode()).digest()
        kodierter_schluessel = base64.urlsafe_b64encode(gehashter_schluessel)

        while len(kodierter_schluessel) < 32:
            kodierter_schluessel += b' '
        return kodierter_schluessel

    def dateiVerschluesseln(self, schluessel, dateipfad):
        fernet = Fernet(schluessel)
        with open(dateipfad, 'rb') as datei:
            datei_daten = datei.read()
        verschluesselte_daten = fernet.encrypt(datei_daten)
        with open(dateipfad, 'wb') as datei:
            datei.write(verschluesselte_daten)
        ##print("Datei \'{}\' verschluesselt.".format(dateipfad))

    def dateiEntschluesseln(self, schluessel, dateipfad):
        fernet = Fernet(schluessel)
        with open(dateipfad, 'rb') as datei:
            verschluesselte_daten = datei.read()
        entschluesselte_daten = fernet.decrypt(verschluesselte_daten)
        with open(dateipfad, 'wb') as datei:
            datei.write(entschluesselte_daten)
        ##print("Datei \'{}\' entschluesselt.".format(dateipfad))

    def datenEntschluesseln(self, schluessel, dateipfad):
        fernet = Fernet(schluessel)
        with open(dateipfad, 'rb') as datei:
            verschluesselte_daten = datei.read()
        entschluesselte_daten = fernet.decrypt(verschluesselte_daten)
        return entschluesselte_daten


