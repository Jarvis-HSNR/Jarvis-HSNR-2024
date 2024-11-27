Software-Download Einleitung und Dateibeschreibung

# Einleitung

1. Dateien installieren 
Für den Systemstart müssen folgende Dateien runtergeladen werden:
* Beispiel.csv
* config.ini
* Geheindaten.csv
* log.csv
* Jarvis.py
* Registration_Lib.py

In diesen zwei Dateien befinden sich lediglich 2 Tools, mit denen man zum Testen und zur Verdeutlichung die Registrierung starten kann und die Daten zu ver- und entschlüsseln. Daher sind diese Tools unrelevant für die Software, sind für eine Abgabe jedoch sinnvoll.
* Tool_DateiVerschluesseln.py
* Datei_Verschluesselung_Lib.py

2.Importieren
Zuerst müssen alle Bibliotheken installiert werden mit dem Befehl:
pip install pyttsx3 SpeechRecognition pyaudio google-generativeai newsapi-python text-to-num langdetect#
Alle anderen Bibliotheken sind Standartbibliotheken und müssen somit nicht mehr installiert werden.

3. Google 2FA
Damit man Gmail verwenden kann für unsere Applikation muss man bei Gmail in den Einstellungen IMAP  aktivieren https://support.google.com/a/answer/105694?hl=de .  Außerdem braucht man ein App-Passwort. Dies kann man auch erst nach einer 2 Faktor Sicherung des Google Accounts einrichten.https://knowledge.workspace.google.com/kb/how-to-create-app-passwords-000009237 Dieses App Passwort wird verwendet um in auf den IMAP Server zu zugreifen.

4. Start
Ist alles nun installiert und alles am gleichen Standort gespeichert, muss nur noch die Datei "Jarvis.py" gestartet werden. 

