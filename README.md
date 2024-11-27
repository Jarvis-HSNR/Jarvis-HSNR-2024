



---
title: "Hackathon:JARVIS"
author: "Niclas Hansen,Pascal Nguyen, Vincent Clark Lipperson, Schervin Jamshidpey, Jonathan Wittmann, Aaron Clemens"
date: "30.20.2024"

---

----------------


## 1 Formales

## 1.1 Angaben zum Projekt

- **Datum: 25.10.2024**
- **Projektname**: **Jarvis**
- **Gruppennummer:** 2
- **Namen der Gruppenmitglieder und deren Verantwortlichkeiten**:
  * \<Niclas Hansen\>, \<1487415\> 
  * \<Pascal Nguyen\>, \<1497111\> 
  * \<Vincent Clark Lipperson\>, \<1506723\> 
  * \<Schervin Jamshidpey\>, \<1489972\>
  * \<Jonathan Wittmann\>, \<1332797\>
  * \<Aaron Clemens\>, \<1502572\>
-------------



## 2 Zweck & Ziel
Das Ziel dieses Projekts ist die Entwicklung eines sprachgesteuerten Assistenzsystems, das grundlegende Funktionen wie Spracheingabe, Sprachausgabe, das Verfassen und Vorlesen von E-Mails sowie die Ausgabe aktueller Top-Nachrichten ermöglicht. Inspiriert von dem Assistenzsystem JARVIS, soll das zu entwickelnde System in der Lage sein, ähnliche Aufgaben im Kontext eines alltäglichen Gebrauchs zu bewältigen. Hierbei steht die Teamarbeit im Vordergrund, da die Erstellung eines solchen Systems neben technischem Wissen auch gute Koordination und Zusammenarbeit erfordert.
Der Zweck des Projekts ist es, den Teilnehmern die Möglichkeit zu geben, durch die praktische Umsetzung eines KI-basierten Assistenzsystems ihre Fähigkeiten in den Bereichen Softwareentwicklung, KI-Integration und Projektmanagement zu erweitern. Durch die Anwendung von Open-Source-Tools und modernen Software-Entwicklungspraktiken soll ein funktionsfähiges System entwickelt werden, das als Grundlage für weiterführende Projekte und Anwendungen genutzt werden kann.

## 3 Entwurf (Meilenstein 1)

## 3.1 Funktionale Anforderungen:
Das zu entwickelnde System soll als sprachgesteuerter Assistent mehrere zentrale Funktionen bereitstellen, um den Anforderungen gerecht zu werden. Im Mittelpunkt stehen die Sprachsteuerung, E-Mail-Verwaltung und die Bereitstellung von Nachrichtenfeeds.
Zunächst muss das System eine Spracheingabe und -ausgabe ermöglichen. Dies bedeutet, dass Benutzer mit dem System über gesprochene Sprache interagieren können. Das System soll Sprachbefehle erkennen, verarbeiten und darauf in natürlicher Sprache antworten können. Die Kommunikation soll flüssig und verständlich ablaufen, wobei der Sprachton möglichst klar und natürlich gestaltet sein sollte, um eine angenehme Benutzererfahrung zu gewährleisten.
Eine weitere wesentliche Funktion des Systems ist die E-Mail-Verwaltung. Hierbei soll das System in der Lage sein, auf Sprachbefehle hin E-Mails zu verfassen, vorzulesen und zu löschen. 
Der Benutzer kann durch Sprachbefehle eine neue E-Mail erstellen, indem er den Empfänger, den Betreff und den Inhalt diktiert. 
Ebenso muss das System E-Mails aus dem Posteingang vorlesen können, wobei der Absender, der Betreff und der Inhalt vollständig wiedergegeben werden. Darüber hinaus soll der Benutzer die Möglichkeit haben, E-Mails durch Sprachbefehle zu löschen, wobei das System sicherstellt, dass die richtige E-Mail ausgewählt und vor der endgültigen Löschung bestätigt wird.
Zusätzlich soll das System einen Nachrichten-Feed bereitstellen. Hierbei kann der Benutzer aktuelle Nachrichten aus verschiedenen Kategorien wie Politik, Wirtschaft, Technologie oder Sport abrufen. Das System soll in der Lage sein, auf Anfrage die neuesten Top-Nachrichten vorzulesen und dem Benutzer auch die Möglichkeit geben, spezifische Nachrichtenkategorien auszuwählen. Der Nachrichten-Feed muss stets auf dem aktuellen Stand sein und die gewünschten Informationen klar und verständlich vermitteln.
Diese Funktionen gewährleisten, dass das System den Anforderungen eines modernen sprachgesteuerten Assistenten entspricht und eine benutzerfreundliche, effiziente Interaktion ermöglicht.


---
## 3.2 Nicht-funktionale Anforderungen: 
Das zu entwickelnde System muss nicht nur funktionale Anforderungen erfüllen, sondern auch in den Bereichen Sicherheit, Performance, Datenschutz und Benutzerfreundlichkeit hohen Standards genügen. Diese Aspekte sind entscheidend, um ein robustes, zuverlässiges und anwenderfreundliches System zu schaffen.

### 3.2.1 Sicherheit:
Die Sicherheit des Systems hat oberste Priorität, da es mit sensiblen Informationen wie E-Mails und persönlichen Daten der Benutzer arbeitet. Es müssen umfassende Sicherheitsmaßnahmen implementiert werden, um potenzielle Bedrohungen wie unbefugten Zugriff, Datenmanipulation oder Cyberangriffe zu verhindern. Hierzu gehört die Integration von Sicherheitsprotokollen wie Verschlüsselungstechniken sowohl für gespeicherte als auch für übertragene Daten. Darüber hinaus muss das System Mechanismen zur Authentifizierung und Autorisierung bereitstellen, um sicherzustellen, dass nur befugte Benutzer Zugang zu den Funktionen erhalten. Regelmäßige Sicherheitsupdates und die Verwendung von Sicherheits-Frameworks (z.B. OWASP oder NIST) sind weitere Maßnahmen, um ein hohes Sicherheitsniveau zu gewährleisten.

### 3.2.2 Performance:
Die Performance des Systems spielt eine entscheidende Rolle für die Benutzererfahrung. Das System muss in der Lage sein, Sprachbefehle schnell und effizient zu verarbeiten und dem Benutzer ohne Verzögerungen Rückmeldungen zu geben. Eine niedrige Latenz bei der Spracheingabe und -ausgabe ist hierbei essenziell. Auch bei der Verarbeitung von E-Mails und der Ausgabe von Nachrichten-Feeds darf es zu keinen spürbaren Verzögerungen kommen. Um eine gleichbleibend hohe Leistung zu gewährleisten, sollte das System auch bei höherer Auslastung, wie bei gleichzeitigen Anfragen mehrerer Benutzer, stabil und performant bleiben. Dies erfordert eine ressourceneffiziente Architektur sowie optimierte Verarbeitungsalgorithmen und Speicherverwaltung.

### 3.2.3 Datenschutz:
Der Schutz der Privatsphäre der Benutzer ist ein weiteres zentrales Kriterium. Das System muss den Vorgaben der Datenschutz-Grundverordnung (DSGVO) entsprechen und sicherstellen, dass personenbezogene Daten nur in dem Umfang erhoben und verarbeitet werden, wie es für die Funktionalität erforderlich ist. Daten wie E-Mails, Sprachaufzeichnungen oder Nachrichten dürfen nur lokal oder in einer sicheren, verschlüsselten Umgebung gespeichert werden. Zudem muss das System die Möglichkeit bieten, dass Benutzer ihre persönlichen Daten einsehen, ändern oder löschen können. Der Zugriff auf gespeicherte Daten sollte klar geregelt sein, und es dürfen keine unbefugten Dritten auf diese Informationen zugreifen können. Datensparsamkeit und Transparenz bei der Datennutzung sind wesentliche Grundprinzipien.

### 3.2.4 Benutzerfreundlichkeit:
Ein benutzerfreundliches System ist der Schlüssel für eine hohe Akzeptanz und Nutzung. Die Benutzeroberfläche sowie die Interaktionen müssen intuitiv gestaltet sein, sodass auch technisch weniger versierte Anwender problemlos damit arbeiten können. Die Spracheingabe sollte präzise und unkompliziert sein, und das System muss in der Lage sein, auch bei verschiedenen Akzenten oder Sprachvariationen korrekte Ergebnisse zu liefern. Ebenso muss die Sprachausgabe klar und verständlich sein. Es sollten keine komplexen technischen Einstellungen notwendig sein, um das System in Betrieb zu nehmen, und die Navigation zwischen den verschiedenen Funktionen muss nahtlos erfolgen. Ein einfaches Onboarding für neue Benutzer sowie die Möglichkeit, auf einfache Weise Hilfe und Support zu erhalten, tragen zusätzlich zur Benutzerfreundlichkeit bei.
Durch die Beachtung dieser Anforderungen an Sicherheit, Performance, Datenschutz und Benutzerfreundlichkeit wird sichergestellt, dass das System sowohl effektiv als auch vertrauenswürdig und nutzerorientiert ist.

---

## 3.3 Systemdesign-Dokumentation: 
### 3.3.1 Architekturdiagramme:

Dieses Dokument beschreibt die Architektur des JARVIS-Tools, wie sie im Architektur Diagramm dargestellt ist. Das System folgt einer logischen Abfolge von Prozessen, die die Benutzerführung, die Funktionalitäten und die Struktur des Programms organisieren.

### 3.3.2 Start des Programmes:

Der Start erfolgt durch die Ausführung einer `.exe`-Datei, die das Hauptfenster der Anwendung öffnet.


### 3.3.3 Visuelle Darstellung von JARVIS:

Nach dem Ausführen der .exe zeigt das System eine visuelle Benutzeroberfläche, die eine visuelle präsentation von JARVIS und ein Terminalfenster beinhaltet. Dies dient als erster Einstiegspunkt für die Benutzerinteraktion, um Logs des Gesprächs aufzuzeichnen.

### 3.3.4 Anmeldung:

Das System fordert den Benutzer zur Eingabe von Benutzername und Passwort auf. Die Anmeldedaten werden verifiziert. Bei erfolgreicher Anmeldung wird der Benutzer weitergeleitet, andernfalls wird eine Fehlermeldung angezeigt.

### 3.3.5 Begrüßung und. Funktionsauswahl:

Nach erfolgreicher Anmeldung wird der Benutzer begrüßt und erhält eine Auswahl an Hauptfunktionen, die er nutzen kann. Zu diesen Funktionen gehören: Chatbot, E-Mail, Senden, News, Lesen,  Logout/Exit

### 3.4 Funktionen:

Das System bietet die folgenden Hauptfunktionen:
#### 3.4.1 Chatbot
Der Chatbot ermöglicht dem Benutzer eine Interaktion in Form eines Dialogs. Der Benutzer kann auf diese Funktion zurückgreifen, um allgemeine Fragen zu stellen oder mit JARVIS zu kommunizieren. Die Funktion bietet eine Möglichkeit zur Rückkehr zur Hauptauswahl.
#### 3.4.2 E-Mail
Diese Funktion umfasst die Verwaltung von E-Mails und bietet zwei Unteroptionen:
#### 3.4.3 Senden
Ermöglicht dem Benutzer das Versenden einer E-Mail. Der Benutzer wird aufgefordert, einen Empfänger und den Text der Nachricht anzugeben. Nach dem Versand wird der Benutzer zur Funktionsauswahl zurückgeführt oder kann eine weitere E-Mail senden.
#### 3.4.4 Lesen
Der Benutzer kann die ersten zehn E-Mails einsehen und hat die Möglichkeit, eine E-Mail auszuwählen, um sie zu lesen. Es werden Optionen angeboten, um E-Mails zu löschen, zu beantworten oder weitere E-Mails zu laden. Der Benutzer kann entweder zur Funktionsauswahl oder zur E-Mail-Auswahl zurückkehren.
#### 3.4.5 News
Der Benutzer wird gefragt, welche Nachrichten er lesen möchte. Daraufhin zeigt das System die neuesten Nachrichten der gewählten Kategorie an. Der Benutzer kann jederzeit zur Funktionsauswahl zurückkehren.
#### 3.4.6 Logout/Exit
Diese Funktion ermöglicht dem Benutzer, das Programm zu beenden. Nach einer Bestätigung wird die Anwendung geschlossen.

---

## 3.5 Architekturdiagramme
### 3.5.1 Mockup
![](https://i.imgur.com/wEv1iX1.jpeg)

### 3.5.2 Architekturplan
![](https://i.imgur.com/1rP5Hq4.png)
![](https://i.imgur.com/WSjAgQO.png)


---

## 3.6 Sicherheitsarchitektur
**Pro- und Contra- Liste für das OWASP-Framework**
Vorteile:
Umfassende Sicherheitsrichtlinien: **OWASP** deckt die häufigsten Schwachstellen ab (z. B. SQL-Injections, XSS), wodurch die Anwendung deutlich sicherer wird.
Branchenstandard: Weit akzeptierter Sicherheitsstandard, der Vertrauen bei Kunden schafft.
Kostenfrei und Open-Source: Keine Lizenzkosten und zahlreiche frei zugängliche Ressourcen und Tools.
Regelmäßige Updates: Ständige Anpassungen an neue Bedrohungen durch die aktive Community.
**Nachteile:**
Implementierungsaufwand: Die umfassenden Maßnahmen erfordern Zeit und Schulung, was Entwicklungsaufwand und Kosten erhöhen kann.
Komplexität für kleinere Projekte: **OWASP** kann für kleinere Teams oder Projekte zu umfangreich sein
Erhöhter Testaufwand: Zusätzliche Sicherheitsmaßnahmen bedeuten mehr Tests und potenzielle Performance-Einbußen.

### 3.6.1 OWASP:
Wir haben uns für **OWASP** entschieden, weil es bewährte Sicherheitsstandards bietet, die uns vor den häufigsten Bedrohungen schützen und Vertrauen bei Kunden schaffen. Zudem hilft es uns, gesetzliche Anforderungen zu erfüllen und die Sicherheit kontinuierlich aktuell zu halten.



**Pro- und Contra-Liste für das NIST-Framework:**
**Vorteile:**
Umfassende Sicherheitsrichtlinien: bietet detaillierte und strukturierte Richtlinien für Sicherheitsmanagement und Risikoanalyse
Branchenspezifische Anpassbarkeit: Frameworks sind flexibel und können auf verschiedene Branchen und Unternehmensgrößen zugeschnitten werden
Fokus auf Risikomanagement: fördert eine proaktive Risikoanalyse und -bewertung, was die Sicherheitsstrategie stärkt.
**Nachteile:**
Hoher Implementierungsaufwand: erfordert Zeit, Ressourcen und Fachwissen für die Umsetzung.
**Komplexität**: kann überwältigend sein und für kleinere Unternehmen zu umfangreich wirken.
Regelmäßige Aktualisierungen nötig: Um relevant zu bleiben, müssen Unternehmen sicherstellen, dass sie die neuesten NIST-Richtlinien regelmäßig anwenden.

### 3.6.2 NIST
**Pro- und Contra-Liste für das MITRE-Framework:**
**Vorteile:**
Umfassende Bedrohungsanalyse: bietet detaillierte Informationen zu Bedrohungen und Angriffstechniken
Standardisierte Terminologie:Verwendung einheitlicher Begriffe und Klassifikationen erleichtert Kommunikation und Verständnis im Sicherheitsteam.
Aktuelle Daten und Trends: aktualisiert regelmäßig seine Datenbanken, was es ermöglicht, sich über die neuesten Bedrohungen und Angriffsvektoren zu informieren.
**Nachteile:**
Komplexität der Implementierung: Die umfassenden Informationen können für neue Benutzer überwältigend sein und erfordern Schulungen.
Ressourcenintensiv: Die Nutzung des MITRE-Frameworks kann zeit- und ressourcenaufwendig sein, insbesondere bei der Analyse und Implementierung.
Fokus auf Bedrohungen: Während es exzellente Informationen zu Angriffen bietet, ist es weniger auf die praktischen Aspekte der Sicherheitsimplementierung ausgerichtet.

### 3.6.3 MITRE

1. **Architekturübersicht**
**Architekturstil**: Defense-in-Depth in Kombination mit Zero Trust und Service Mesh, um die einzelnen Schichten abzusichern und die Kommunikation der Services zu kontrollieren.

**Komponenten:**
Eingabe und Verarbeitungs-Module: Sprach- und Textverarbeitung, Audioeingabe und -ausgabe.

**E-Mail-Modul:** Zugriff und Verwaltung der E-Mails über IMAP.
API-Modul (NewsAPI): Abrufen von Nachrichten über eine gesicherte API.
Sicherheitsdienste: Secrets Management, Logging und Monitoring, MFA und RBAC.
2. **Architekturdiagramm und Komponentenbeschreibung**
Hauptarchitekturkomponenten
**Frontend-Komponenten:**
Mikrofon und Audiowiedergabe: Sprachaufnahmen und -ausgabe werden lokal verarbeitet und an die Sprachverarbeitung übergeben.
Security Layer für Input Validation: Diese Ebene prüft und validiert alle Eingaben (z. B. Sprachbefehle), um Missbrauch zu vermeiden. Hier kommt die Defense-in-Depth Strategie zur Anwendung.

### 3.6.4 Backend-Komponenten:
**E-Mail Service Modul:**
Verbindet sich zu IMAP mit mutual TLS (mTLS) zur sicheren Authentifizierung.
Nutzt Environment Variables für Benutzername und Passwort, um sensible Daten nicht im Code zu speichern.
Implementiert RBAC und MFA, um sicherzustellen, dass nur autorisierte Benutzer E-Mails abrufen können.
**NewsAPI Service Modul:**
Schließt sich mit einem API-Schlüssel an die NewsAPI an.
API-Schlüssel werden über ein Secrets Management System (z. B. AWS Secrets Manager) verwaltet.
Ein API-Gateway schützt den Zugang, ermöglicht Logging und stellt sicher, dass der Datenverkehr nur von autorisierten IP-Adressen erfolgt.

**Speech-to-Text und Text-to-Speech Modul:**
Input- und Output-Verarbeitung erfolgt lokal, und alle Daten werden über Zero Trust Access Controls kontrolliert.
Sicherheitsmodule:
Zero Trust Identity and Access Management (IAM): Identitäts- und Zugriffsverwaltung stellt sicher, dass jede API- oder E-Mail-Verbindung anhand von Benutzerkontext (Standort, Geräteidentifikation) überprüft wird.
Secrets Management: API-Schlüssel und Zugangsdaten werden hier gespeichert, um sicherzustellen, dass nur autorisierte Services auf die Daten zugreifen können.

**Logging und Monitoring:**
Jeder Zugriff auf E-Mail und NewsAPI wird geloggt und zentral überwacht, um ungewöhnliche Aktivitäten schnell zu erkennen.
Incident Detection und Response System (IDS) überwacht in Echtzeit auf potenzielle Angriffe oder verdächtiges Verhalten.
Service Mesh Layer (optional):
Falls in Zukunft mehr APIs hinzukommen, ermöglicht dieser Layer den Aufbau eines Netzwerks aus Microservices mit mutual TLS und Traffic Monitoring zwischen den Services.

![](https://i.imgur.com/5jxMQBn.png)
## 3.7 Sicherheitsarchitektur Anwendung: 
Im folgenden Text wird der Aufbau der Sicherheitsarchitektur erläutert mit Berücksichtigung von OWASP.


### 3.7.1 Server Architektur

Die Applikation wird über einen Proxmox Server mit einem Unix Betriebssystem ausgeführt. 
Bei der Unix Version haben wir uns für Debian entschieden. 
Zunächst haben wir auch mit anderen Versionen wie Fedora, Alpine und Ubuntu geliebäugelt, jedoch entschlossen wir uns schließlich für Debian, aufgrund der gegebenen Stabilität die Debian bietet, was Zuverlässigkeit angeht, welche bei Alpine nicht so ganz gegeben wäre. 
Zudem erlaubt es Debian das Ganze ziemlich minimalistisch, das System zu gestalten und die Ressourcen des Systems effizient zu nutzen (Während Ubuntu und Fedora mehr Ressourcen benötigen) . 
Außerdem gibt es nicht wie bei Alpine die Probleme bezüglich der Kompatibilität bezüglich der Python Libraries.

Pro Debian:
 - Stabilität
 - Gute Kompatibilität bezüglich Python
 - Ressourcen Effizient
 - Proxmox läuft auch über Debian so dann auch eine gute Kompatibilität
 - Regelmäßige Sicherheitsupdates
 
Nun benötigt es die Einrichtung des Servers.
Zunächst wird in /etc/sysctl.conf die Netzwerk Sicherheitseinstellungen angepasst.
 - Deaktivieren der Annahme von Source-Routed Packets (gegen source routing Angriffen )
 - Deaktivieren der Annahme von ICMP redirects (gegen man in the middle Angriffe)
 - Aktivieren von Source-Route Verification (gegen IP spoofing)
 
Darauf folgend wird mit dem Proxmox Befehl pct create ein Linux Container erstellt. Wir legen Speicherplatz, CPU-Kerne und Netzwerkkonfiguration. 
Die Privilegien werden aufgehoben, um potenziellen Schaden im Falle einer Kompromittierung zu reduzieren. 
Zur weiteren Einrichtung wird das System aktualisiert und sicherheitsrelevante Pakete installiert:
 - UFW für Netzwerksicherheit
 
Wir konfigurieren UFW so, dass standardmäßig der gesamte eingehende
Datenverkehr abgelehnt und nur bestimmte Ports zugelassen werden.
 - Fail2ban gegen Brute Force Angriffe
 
Zum Schutz vor wiederholten fehlgeschlagenen Anmeldeversuchen haben wir Fail2ban eingerichtet
 - AppArmor zur Anwendung Isolierung, um ihren Zugriff auf Systemressourcen einzuschränken.
  - Auditd zur Systemprüfung
 - RKHunter zum erkennen von rootkits
 - ClamAV zum Virenscannen 
 
Nun wird ein dedizierter Benutzer, unter dem die Anwendung ausgeführt wird, und durch Isolierung die Sicherheit erhöht. Wir erstellen einen systemd service mit Sicherheitsverbesserungen wie: 
- keine neuen Privilegien
- private /tmp
- Read only root filesystem
- kein Zugang zu /home
- eingeschränkte Funktionen
- protected kernel Einstellungen

Zur Überwachung wird Prometheus für die Metrik Erfassung und Grafana für die Visualisierung eingerichtet. 
Dadurch können wir Systemressourcen und Anwendung Metriken überwachen und so potenzielle Sicherheitsprobleme erkennen


### 3.8 Code Architektur

#### 3.8.1 Sichere Anmeldeinformationsverwaltung:
-
 Statt die Anmeldeinformationen fest in den Quellcode einzugeben werden Variablen verwendet. Dies verhindert die Offenlegung von Anmeldeinformationen in der Versionskontrolle, eine einfache Rotation der Anmeldeinformationen und befolgen das Prinzip der geringsten Privilegien
```python
# Unsafe
email_user = ‘jarvis505hsnr@gmail.com’
email_pass = ‘xgkj unvv xbqm bxno’

#Safe
from dotenv import load_dotenv
import os

load_dotenv()
email_user = os.getenv(‘EMAIL_USER’)
email_pass = os.getenv(‘EMAIL_PASSWORD’) 
```
#### 3.8.2 API Schlüsselschutz:
- Die API Schlüssel sollten als vertrauliche Anmeldeinformationen behandelt und sicher gespeichert werden
```python
#Unsafe
newsapi = NewsApiClient(api_key=’27b11c408f6e41cdb927b1b3e4943949’)

#Safe
newsapi = NewsApiClient(api_key=os.getenv(‘NEWS_API_KEY’))
```

#### 3.8.3 Eingabevalidierung und -bereinigung
- Zur Verhinderung von Befehlinjections, sodass nur erwartete Eingabeformate verarbeitet werden. Reduzierung von Risiko von böswilligen Eingabeausnutzungen
```python
def sanitize_input(text):
      
      if not text:
             return None
     sanitized = ‘’.join(char for char in text if char.isalnum() or char.isspace())
     return sanitized.lower()

def get_audio(language=”en-US”):
      
      if said:
              said = sanitize_input(said)
      return said
```

#### 3.8.4 Fehlerbehandlung und Protokollierung:
- Dies hilft beim Debuggen ohne, dass dabei vertrauliche Informationen preiszugeben und zu dem bietet dies ein Verständnis und eine Nachvollziehbarkeit von security events
```python
import logging
form logging.handlers import RotatingFileHandler

def setup_logging():
       logging.basicConfig(
              handlers=[RotatingFileHandler(
                       ‘application.log’,
                        maxBytes=100000,
                        backupCount=5
                 )],
                 level=logging.INFO,
                 format=’%(asctime)s - %(levelname)s - %(message)s’
)

def secure_speak(text):

      try:
           speak(text)
      except Exception as e:
             logging.error(f”Speech error: {str(e)}”)
             raise   
```    
#### 3.8.5 Verbesserungen der E-Mail Sicherheit:
- SSL/TLS Verschlüsselung, Implementierung von Verbingstimeouts
```python
def connect_to_email():
       
      try:
            if not email_user or not email_pass:
                     raise ValueError(“Email credentials not configured”)
             mail = imaplib.IMAP4_SSL(‘map.gmail.com’, timeout=30)
             mail.login(email_user, email_pass)
             return mail 
     expect imaplib.IMAP4.error as e:
            logging.error(f”IMAP connection error: {str(e)}”)
     except Exception as e:
               logging.error(f”Email connection error: {str(e)}”)
               raise
```
#### 3.8.6 Rate Limits:
- Verhindert API Missbrauch, Schutz vor DOS Angriffen und verwaltet zu dem den Ressourcenverbrauch
```python
from functools import wraps
import time

def rate_limit(max_calls, time_frame):
      
      calls= []
      
      def decorator(func):
             @wraps(func)
             def wrapper(*args, **kwargs):
                    now = time.time()
                    calls[:] = [c for c in calls if c > now - time_frame]
                    if len(calls) > max_calls:
                               raise Exception(“Rate limit exceeded”)
                    calls.append(now)
                    return func(*args, **kwargs)
               return wrapper
       return decorator

@rate_limit(max_calls=5, time_frame=60)
def get_news():
….
``` 
#### 3.8.7 Sitzungsverwaltung:
- Verhinderung von Session Hijacking, sowie um die ordnungsmäßige Bereinigung der Ressourcen sicherzustellen
```python
class EmailSession:
       def _init_(self):
              self.mail = None
              self.session_start = None
              self.max_session_time = 300
       def start_session(self):
              self.mail = connect_to_email()
              self.session_start = time.time()
       
       def check_session_valid(self):
              if not self.session_start:
                    return False
              return (time.time() - self.session_start) < self.max_session_time
       def end_session(self):
              if self.mail:
                    self.mail.logout()
                    self.mail = None
                    self.session_start = None
```   
#### 3.8.8 Inhaltssicherheit:
- Zur Verhinderung von XSS Angriffen, Blockierung von potenziellen schädlichen Inhalten und validiert Inhalte vor der Verarbeitung
```python
def validate_email_content(msg):
       
       if msg is None: 
               return False

       suspicious_patterns = [‘<script>’, ‘javascript:’, ‘data:’]
       for pattern in suspicious_pattern:
             if pattern in str(msg).lower():
                   logging.warning(f”Suspicious content detected: {pattern}”)
                   return False
       return True
```
#### 3.8.9 Sichere Konfiguration:
- Ermöglicht die einfache Wartung von Sicherheitsparametern, Ermöglichung von schnellen Updates der Sicherheitsrichtlinien und ermöglicht die Zentralisierung der Sicherheitskonfiguration 
```python
#config.py
SECURITY_CONFIG = {
                 ‘MAX_LOGIN_ATTEMPTS’:3,
                 ‘SESSION_TIMEOUT’: 300,
                  ‘ALLOWED_LANGUAGES’: [‘en-US’, ‘de-DE’],
                  ‘MAX_AUDIO_LENGTH’: 60,
                  ‘SECURE_HEADER’: {
                            ‘X-Content-Type-Options’: ‘nosniff’,
                            ‘X-Frame_Options’: ‘DENY’,
                            ‘X-XSS-Protection’: ‘1; mode=block’
                   }

}

```
---
## 3.9 Tool-Liste: 

### 3.9.1 News Tools:
**"News API"**
**Funktion:** Eine News API ermöglicht den Zugriff auf Nachrichten und Artikel von verschiedenen Quellen und liefert aktuelle Informationen nach Kategorien, Sprachen oder Ländern.

**Vor- und Nachteile:** Die API liefert standardisierte Daten und ist einfach zu integrieren, ist jedoch oft mit begrenztem Zugriff oder Kosten verbunden.

**"Web-Scraping"**
**Funktion**: Web-Scraping sammelt gezielt Informationen direkt von Websites durch Extraktion von HTML-Inhalten.

**Vor- und Nachteile:** Web-Scraping erlaubt flexiblen Zugriff auf beliebige Daten, jedoch kann es rechtliche Einschränkungen und technische Blockaden durch die Website geben.

**"RSS-Feeds"**
**Funktion:** RSS-Feeds stellen Inhalte von Websites in einem standardisierten Format zur Verfügung und halten Nutzer automatisch über Aktualisierungen auf dem Laufenden.

**Vor- und Nachteile:** RSS ermöglicht einfache und schnelle Aktualisierungen, jedoch sind Inhalte begrenzt auf den Feed, und es ist keine Interaktion möglich.

---

### 3.9.2 Chatbots:

**“Rasa”**
**Funktion:** Ein leistungsstarkes Open-Source-Framework für die Erstellung von KI-gestützten Chatbots mit natürlicher Sprachverarbeitung (NLP). Rasa bietet eine Umgebung zum Trainieren und Ausführen von Bots, ohne dass eine externe API notwendig ist.

**Vor- und Nachteile:** Bietet sowohl Dialogmanagement als auch NLP, unterstützt maschinelles Lernen und ermöglicht die Implementierung komplexer Bots.

**“Botpress”**
**Funktion:** Eine quelloffene Plattform für Chatbots, die lokal installiert werden kann. Botpress hat eine benutzerfreundliche Oberfläche und bietet viele vordefinierte Funktionen und Module.

**Vor- und Nachteile** Keine Programmierkenntnisse erforderlich, unterstützt visuelle Workflows und einfache Einrichtung, keine externe API nötig.

**“DeepPavlov”**
**Funktion:** Ein Open-Source-Framework für Conversational AI und Chatbots, das vortrainierte NLP-Modelle enthält. DeepPavlov kann auf benutzerdefinierten Daten trainiert werden und lokal verwendet werden.

**Vor- und Nachteile:** Ideal für NLP-Chatbots, unterstützt die Sprachanalyse und Dialogverwaltung, keine API erforderlich.

---


### 3.9.3 Sicherheits-tools:

**“Nmap”**
**Funktion:** Ein weit verbreitetes Netzwerk-Scanning-Tool, das Ports, Dienste und Betriebssysteme erkennt. Es eignet sich perfekt für die Überwachung von Netzwerken und das Auffinden von Schwachstellen.

**Vor- und Nachteile:** Schnelles Scannen und detaillierte Analyse von Netzwerken, besonders nützlich für Netzwerksicherheit und Schwachstellenscans.

**Vor- und Nachteile:** Detaillierte Analyse des Netzwerkverkehrs, Open-Source, benutzerfreundliche grafische Benutzeroberfläche.

**“OpenVAS (Greenbone Vulnerability Management)**
**Funktion:** Ein Schwachstellen-Scanner, der detaillierte Sicherheitsberichte und Schwachstellenbewertungen bietet.

Vor- und Nachteile: Umfassende Schwachstellen-Datenbank, automatisiertes Scannen und Reporting, kein Bedarf an einer externen API.

**“Metasploit Framework”**
**Funktion**: Eine Sammlung von Exploits und Sicherheitstools, die Penetration-Tester und Forscher verwenden, um Netzwerke und Systeme zu überprüfen.

**Vor- und Nachteile:** Große Auswahl an Exploits und Payloads, stark angepasst an professionelle Penetrationstests, Open-Source.

**“John the Ripper”**
Funktion:Ein Passwort-Cracking-Tool zur Überprüfung der Passwortstärke und für Schwachstellenanalysen.

Vor- und Nachteile: Unterstützt eine Vielzahl von Hash-Formaten, nützlich für das Überprüfen von Passwortsicherheitsstandards.

**"UFW"**
Funktion: Eine benutzerfreundliche Firewall für Linux-Systeme.

**Vor- und Nachteile:**

**Vorteile**: Einfache Einrichtung und Verwaltung, ideal für grundlegende Firewall-Anforderungen, besonders nützlich für Einsteiger.
**Nachteile**: Begrenzte Konfigurationsmöglichkeiten für komplexere Netzwerksicherheitsanforderungen.

**"Fail2ban"**
**Funktion**: Ein Intrusion-Prevention-Tool, das wiederholte fehlerhafte Anmeldeversuche blockiert.

**Vor- und Nachteile:**

**Vorteile**: Effektiv gegen Brute-Force-Angriffe, flexibel konfigurierbar, reduziert Sicherheitsrisiken bei Remote-Zugriffen.
**Nachteile**: Bei Fehlkonfiguration können auch berechtigte Nutzer blockiert werden, blockt nur IP-basierte Angriffe.

"**AppArmor**"
**Funktion**: Ein Sicherheitsmodul zur Kontrolle von Anwendungsberechtigungen auf Linux-Systemen.

**Vor- und Nachteile:**

**Vorteile**: Granulare Kontrolle über Anwendungszugriffe, verbessert die Systemsicherheit, integriert in viele Linux-Distributionen.
**Nachteile**: Erfordert fortgeschrittene Kenntnisse für das Erstellen eigener Profile, nicht alle Anwendungen werden standardmäßig unterstützt.

"**Auditd**"
**Funktion**: Ein System zur Protokollierung und Überwachung von sicherheitsrelevanten Ereignissen auf Linux-Systemen.

**Vor- und Nachteile:**

**Vorteile**: Bietet detaillierte System-Logs, unterstützt Compliance-Anforderungen, flexibel konfigurierbar.
**Nachteile**: Erzeugt bei umfangreichen Logs großen Speicherbedarf, kann Performance-Einbußen verursachen.

"**RKHunter**"
**Funktion**: Ein Tool zur Überprüfung auf Rootkits und andere bösartige Dateien.

**Vor- und Nachteile:**

**Vorteile**: Erkennt eine Vielzahl an Rootkits und bösartigen Tools, einfach zu installieren und zu nutzen.
**Nachteile**: Erfordert regelmäßige Aktualisierungen der Signaturen, gelegentlich Fehlalarme.

**"ClamAV"**
**Funktion**: Ein Open-Source-Virenscanner für Linux.

**Vor- und Nachteile:**

**Vorteile**: Schützt vor Viren, Malware und Trojanern, kostenlos und Open Source, unterstützt On-Demand- und Echtzeit-Scanning.
**Nachteile**: Höhere CPU-Auslastung bei Scans, begrenzter Schutz bei neuester Malware ohne aktuelle Signaturen.

---

### 3.9.4 Email-Protokolle:

**“IMAP4”**
**Funktion:** IMAP4 ist ein Protokoll, das E-Mails von IMAP4-Servern synchronisiert und lokal speichert, meist in Maildir- oder Mbox-Formaten.
Zwei-Wege-Synchronisation (zwischen Server und lokalem Speicher).
Speicheroptionen in Maildir oder Mbox-Formaten für plattformübergreifende Kompatibilität.
Flexibel konfigurierbar durch eine .conf-Datei.

**Vor- und Nachteile:** Effizient für Benutzer, die mit mehreren E-Mail-Konten offline arbeiten: automatische Synchronisation möglich. 
**Nachteil**:
Bedarf an Konfiguration und ist hauptsächlich CLI-basiert, was eventuell eine Einarbeitung erfordert.

**“Offline SMTP”**
**Funktion**: Für einfache lokale Tests und Entwicklungszwecke sind Papercut, Mailhog und smtp4dev gut geeignet. Postal ist die beste Wahl für Benutzer, die mehr Kontrolle und Optionen für umfangreiche Tests benötigen. FakeSMTP bietet eine portable, plattformübergreifende Lösung für Testzwecke ohne SMTP-Server, während Mailhog besonders durch seine Weboberfläche und REST-API in CI/CD-Umgebungen attraktiv ist.

**Vor- und Nachteile:** SMTP ist ein weit verbreiteter, standardisierter Protokollstandard, der die Kommunikation und Kompatibilität zwischen verschiedenen E-Mail-Diensten sicherstellt.
**Nachteile**: Keine End-to-End-Verschlüsselung: Standardmäßig verschlüsselt SMTP keine Nachrichteninhalte, zusätzliche Verschlüsselung (z.B. TLS) muss manuell implementiert werden.
Anfällig für Spam: Die Einfachheit des Protokolls wird oft missbraucht, um Spam-E-Mails zu senden, wodurch zusätzliche Spam-Filter notwendig werden.
Fehlende Rückverfolgbarkeit: E-Mails lassen sich leicht fälschen (Spoofing), weshalb zusätzliche Authentifizierungsmaßnahmen wie SPF und DKIM erforderlich sind, um Absender zu verifizieren.

---
### 3.9.5 Voice-Tools:
**“MetaVoice-1B”**
**Funktion**: Eine leistungsstarke Sprachausgabe-Engine, die Stimmen mit hoher Natürlichkeit und emotionalem Ausdruck für KI-Anwendungen wie Jarvis erzeugt.



**Vor- und Nachteile:**

**Vorteile**: Hohe Natürlichkeit und emotionale Tiefe der Stimmen, kann unterschiedliche Sprachstile und Stimmungen darstellen, ideal für personalisierte Assistenten und immersive Anwendungen.
**Nachteile:** Benötigt hohe Rechenleistung, eventuell kostenpflichtige Lizenzierung, für individuelle Implementationen eventuell zusätzliche API- oder Serveranbindung erforderlich."


---


## 3.10 Kostenrechnung für das Projekt
### 3.10.1 Personalkosten:
**Dauer**: **3** Monate
Teamaufteilung: **6** Personen (**3** Entwickler für Codierung und **3** Teammitglieder für Systemarchitektur und Dokumentation)
**Monatliches Gehalt pro Person:** **4.000** EUR
**Berechnung**:
**Entwicklerkosten**:
**3** Entwickler × **4.000** EUR × **3** Monate = **36.000** EUR
Systemarchitektur und Dokumentation:
**3** Personen × **4.000** EUR × **3** Monate = **36.000** EUR
Gesamte Personalkosten: **72.000**EUR
### 3.10.2 Hardware- und Stromkosten:
**Hardwareanschaffungskosten**: Für Server und leistungsstarke Entwicklungs-PCs
Einmalige Kosten: **2.500** EUR
Stromkosten für Hardwarebetrieb: ca. **500** EUR pro Monat
**Berechnung**:
**Hardware**: **2.500** EUR
**Stromkosten**:
**500** EUR × **3** Monate = **1.500** EUR
Gesamte Hardware- und Stromkosten: **4.000** EUR
### 3.10.3 Softwarelizenzen und Tools:
**Benötigte Softwarelizenzen für das Team:** Entwicklungsumgebungen, Sicherheitstools, Dokumentationstools usw.
Durchschnittlich **500** EUR pro Person
**Berechnung**:
**Lizenzkosten pro Person:**
**6** Personen×**500** EUR= **3.000** EUR
Gesamtkosten für Softwarelizenzen und Tools: **3.000** EUR
### 3.10.4 Infrastruktur und IT-Dienste:
**Serverkosten**: Für Cloud-Hosting, Datenbanken und zusätzliche Ressourcen
**Monatlich**: **1.000** EUR
**Wartung und IT-Support:** Zur Sicherstellung der Verfügbarkeit und Wartung der Server
Monatliche externe IT-Wartungskosten: **500** EUR
**Berechnung:
Server-Mietkosten:**
**1.000** EUR × **3** Monate = **3.000** EUR
**Wartung und IT-Support:**
**500** EUR × 3 Monate = **1500**
Gesamtkosten für Infrastruktur und IT-Dienste: **4.500** EUR
### 3.10.4 Testen und Qualitätssicherung (QS):
**Lizenzkosten für Test- und QS-Tools:** Einmalig **1.500** EUR
Externe Testdienste: Beauftragung externer Tester zur Sicherstellung der Qualität und Funktionalität
Einmalige Kosten: **2.000** EUR
**Berechnung**:
**Test-Tool-Lizenzen**: **1.500** EUR
**Externe Tests:** **2.000** EUR
**Gesamte Test- und Qualitätssicherungskosten**: **3.500** EUR

## 3.10.5 Gesamtkostenübersicht



|Kostenkategorie|Betrag (EUR)|
| -------- | -------- |
|**Personalkosten** |72.000|
|**Hardware und Strom**|4.000|
|**Softwarelizensen und Tools**|3.000|
|**Infrastruktur und iT- Dienste**|3.900|
|**Testen und Qualitätssicherung**|3.500|
|**Gesamtkosten**|**86.400**

## 3.11 Verkaufs- und Lizenzierungsstrategie

### 3.11.1 Direktverkauf des Projekts:
**Verkaufspreis**: **125.000** EUR
**Gewinn**:
**125.000** EUR − **86.400** EUR = **38.600**
**ROI** von ca. **44,7 %**

### 3.11.2 Lizenzmodell mit zusätzlichem Supportvertrag
**Monatliche Lizenzgebühr:** **4.000 EUR**
Supportvertrag: Zusätzlich **1.50**EUR monatlich für Updates und Wartung
**Jährliche Einnahmen:**
(**4.000** EUR + **1.500** EUR) × **12** = **66.000** EUR
ROI über **2 Jahre:** Bei einer Nutzung über **2** Jahre ergibt dies einen ROI von **52,7 %**

## 3.12 Kostenplan für SLAs (Service Level Agreements)

### 3.12.1 Basis-SLA:
**Leistungsumfang**:
Monatlicher Systemcheck und Sicherheitsupdate
Reaktionszeit auf Supportanfragen: **48** Stunden
Verfügbarkeit von **95 %**
Kosten: **500** EUR pro **Monat**

### 3.12.2 Standard-SLA:
**Leistungsumfang**:
Monatlicher Systemcheck, Sicherheitsupdates und Backup-Management
Reaktionszeit auf Supportanfragen: **24** Stunden
Verfügbarkeit von **98 %**
Zugang zu einem Supportportal mit Ticketing-System
Kosten: **1.000** EUR pro Monat

### 3.12.3 Premium-SLA:
**Leistungsumfang:**
Wöchentliche Systemüberwachung, tägliche Backups und erweiterte Sicherheitsupdates
Reaktionszeit auf Supportanfragen: **12 Stunden**
Verfügbarkeit von **99,5 %**
Dedizierter Ansprechpartner und **24/7-Hotline** für dringende Anfragen
Priorisierte Fehlerbehebung und proaktive Systemüberwachung
**Kosten:** **2.500** EUR pro Monat
### 3.12.4 Individual-SLA (Kundenspezifisch):
**Leistungsumfang**:
Anpassbarer Umfang je nach Kundenbedürfnissen
Zusätzliche Dienstleistungen wie maßgeschneiderte Anpassungen, mehrstufige Backup-Strategien, erweiterte Sicherheitsanalysen oder regelmäßige Schulungen
Flexibler Zugang zu einem Entwicklerteam für Funktionsanpassungen
**Kosten:** Auf Anfrage, je nach spezifischem Bedarf und SLA-Umfang
Beispielhafte Berechnung: **5.000 EUR** pro Monat für maßgeschneiderte Lösungen mit Reaktionszeiten von unter **6 Stunden** und garantierter Verfügbarkeit von **99,9 %**


### 3.12.5 Zusätzliche Kosten für SLA-Leistungen
#### 3.12.6 Notfallgebühr: 
Für besonders dringende Anfragen außerhalb der vereinbarten SLA-Reaktionszeiten werden zusätzliche Gebühren berechnet werden ( **150** EUR pro Stunde).
#### 3.12.7 Regelmäßige Systemerweiterungen: 
Bei bestimmten SLA-Stufen könnte der Kunde auf regelmäßige Funktionsupdates und Erweiterungen zugreifen. Dafür könnten monatlich zusätzliche **500–1.000** EUR berechnet werden

---
## 3.12.8 Zusammefassung der SLA- Kosten


| SLA- Option | Leistungsumfang | Verfügbarkeit | Reaktionszeit | Kosten pro Monat  |
| ---------  | -------- | -------- | -------- | -------- |
|Basis- SLA|Systemchecks, Sciherheitsupdates|95%|48 Stunden|500|
|Standard- SLA|Systemcheck, Sicherheitsupdates, Backup-Management|98%|24 Stunden|1000|
|Premium- SLA|Tägliche Backups, erweiterte Sicherheitsupdates|99,5%|12 Stunden|2500|
|Individual- SLA|Maßgeschneiderte Optionen nach Kundenbedarf|99,9%|< 6 Stunden|5000+|

---

## 3.13 Grundgerüst des Codes Teil 1

Projektstart: Wahl der Ressourcen und erste Schritte
Um eine solide Basis zu schaffen, entschieden wir uns, uns an dem https://www.geeksforgeeks.org/how-to-make-a-voice-assistant-for-e-mail-in-python/-Leitfaden zur E-Mail-Sprachsteuerung zu orientieren. 

#### 3.13.1 Sprachausgabe mit ```pyttsx3```

Für die Sprachausgabe haben wir `pyttsx3` genutzt. Die Funktion `speak()` gibt uns die Möglichkeit, Nachrichten per Text-to-Speech vorzulesen:

```python 
import pyttsx3

def speak(text):
    engine = pyttsx3.init()
    engine.say(text)
    engine.runAndWait()
```
Mit ```speak()```können wir z.B. die Begrüßung umsetzen: 
```python 
speak("Willkommen im Mail-Service.")
```

#### 3.13.2 Spracheingabe mit ``` speech_recognition```

Um Sprachbefehle zu erkennen, verwenden wir die Bibliothek ```speech_recognition```. Die Funktion ```get_audio()```erfasst die Audio-Eingaben:

```python
import speech_recognition as sr

def get_audio():
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        print("Ich höre zu...")
        audio = recognizer.listen(source)
    try:
        text = recognizer.recognize_google(audio, language='de-DE')
        print(f"Du hast gesagt: {text}")
        return text.lower()
    except sr.UnknownValueError:
        speak("Entschuldigung, ich habe das nicht verstanden.")
        return ""
```
Diese Funktion hört dem Nutzer zu und wandelt die Sprache in Text um, den wir später für Befehle verwenden.

#### 3.13.3 Google Gmail-API und Authentifizierung
Die Verbindung zur Gmail-API war ein wesentlicher Schritt. Dafür haben wir OAuth2 verwendet, um die Berechtigungen für den E-Mail-Zugriff zu sichern. Einmal authentifiziert, können wir auf E-Mails zugreifen, ohne jedes Mal den Zugang erneut einzugeben:
```python
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle

def authenticate_gmail():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', ['https://www.googleapis.com/auth/gmail.readonly'])
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    service = build('gmail', 'v1', credentials=creds)
    return service
```
#### 3.13.4 Email überprüfen mit ```check_mails()```
In ```check_mails()``` werden die ungelesenen E-Mails ermittelt und optional vorgelesen. Die Funktion überprüft die Anzahl ungelesener Nachrichten und fragt, ob der Nutzer diese vorlesen lassen möchte:
```python 
def check_mails(service):
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], q='is:unread').execute()
    messages = results.get('messages', [])

    if not messages:
        speak("Keine neuen Nachrichten.")
    else:
        speak(f"Du hast {len(messages)} neue Nachrichten.")
        for msg in messages[:3]:  # Beschränkung auf die ersten 3 Nachrichten
            txt = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = txt['snippet']
            speak(f"Nachricht: {snippet}"
```
Hier wird der Nachrichtentext extrahiert und als Vorschau vorgelesen. Nutzer*innen können wählen, ob die Nachrichten weiter vorgelesen werden sollen.
### 3.14 Herausforderungen und Lösungen 

#### 3.14.1 Mikrofon-Eingang einstellen
Anfangs wurde der Mikrofoneingang nicht zuverlässig erkannt. Nach einigen Anpassungen, etwa an den ```device_index```, konnten wir eine stabile Verbindung schaffen`
#### 3.14.2 Optimierung durch Threading
Um das Programm nicht zu blockieren, haben wir die Spracherkennung in einem separaten Thread laufen lassen. Dadurch kann das Programm kontinuierlich auf Sprachbefehle reagieren, während es E-Mails abruft:
```python
import threading

def start_voice_assistant():
    while True:
        command = get_audio()
        if "lies nachricht" in command:
            check_mails(service)
```
## 3.15 Grundgerüst Teil 2 
#### 3.15.1 Text-to-Speech mit ```speak()```
Zur Verbesserung der Sprachausgabe haben wir den `voice index` auf 2 gesetzt, um die Ausgabe in einer englischen Stimme zu realisieren. Dies verhindert die Vermischung deutscher und englischer Aussprachen.
```python
import pyttsx3

def speak(text):
    """
    Funktion zur Umwandlung von Text in Sprache.

    Args:
        text (str): Der Text, der in Sprache umgewandelt werden soll.
    """
    engine = pyttsx3.init()
    voices = engine.getProperty('voices')
    engine.setProperty('voice', voices[2].id)  # Englischsprachige Stimme
    rate = engine.getProperty('rate')
    engine.setProperty('rate', rate - 20)
    engine.say(text)
    engine.runAndWait()
```
#### 3.15.2 Spracheingabe mit ```get_audio()```
Die Funktion ```get_audio()``` wurde aktualisiert, um die Mikrofonqualität zu verbessern. Einige Fehlerbehandlungen wurden hinzugefügt, um die Nutzerfreundlichkeit zu erhöhen, und die ```pause threshold``` wurde angepasst, um eine bessere Erkennungsrate zu erreichen`
```python 
import speech_recognition as sr

def get_audio():
    """
    Funktion zur Erfassung und Erkennung von Spracheingaben.

    Returns:
        str: Der erkannte Text, oder `None`, falls keine Eingabe erkannt wurde.
    """
    r = sr.Recognizer()
    with sr.Microphone(device_index=1) as source:
        r.pause_threshold = 1
        r.adjust_for_ambient_noise(source, duration=2)
        print("Listening...")
        try:
            audio = r.listen(source, timeout=5)
            said = r.recognize_google(audio, language="en-US")
            print(f"You said: {said}")
        except sr.WaitTimeoutError:
            print("Listening timed out.")
        except sr.UnknownValueError:
            print("Google Speech Recognition konnte keine Eingabe verstehen.")
        except sr.RequestError as e:
            print(f"Fehler bei der Anfrage an Google Speech Recognition: {e}")
    return said.lower() if said else None
```
#### 3.15.3 Optimierung der Funktion ```check_mails()```
Um alle vorhandenen E-Mails ohne Einschränkung überprüfen zu können, wurden einige Zeilen entfernt und die Nachrichtenanzahl erhöht.
```python 
def check_mails(service):
    """
    Funktion zur Überprüfung und Verarbeitung von E-Mails.

    Args:
        service: Der authentifizierte Gmail-API-Service.
    """
    results = service.users().messages().list(userId='me', labelIds=["INBOX"], q="category:Primary").execute()
    messages = results.get('messages', [])

    if not messages:
        print("Keine neuen Nachrichten.")
        speak("Keine neuen Nachrichten.")
    else:
        speak(f"{len(messages)} neue Nachrichten gefunden.")
        for msg in messages:
            try:
                message = service.users().messages().get(userId='me', id=msg['id'], format='metadata').execute()
                sender = next(header['value'] for header in message['payload']['headers'] if header['name'] == "From")
                speak(f"Nachricht von {sender}")
                user_input = get_audio()
                if user_input == "read":
                    print(message['snippet'])
                    speak(message['snippet'])
                elif user_input == "delete":
                    service.users().messages().delete(userId='me', id=msg['id']).execute()
                    speak("Nachricht gelöscht.")
                else:
                    speak("Nachricht übersprungen.")
            except Exception as e:
                print(f"Fehler beim Abrufen der E-Mail: {e}")
```
#### 3.15.4 Google API-Scopes und das Problem damit
Um nun das Löschen von Emails zu implementieren, kamen wir zu einem Problem, das mit den Scopes oder auch Rechten von Google zu tun hatte.
Unsere Grundidee für das Löschen von E-Mails im Code sah so aus:
```python
  speak("To delete an email, say delete.")
        speak("And for not reading, say leave.")

        for message in messages:
            try:
                msg = service.users().messages().get(userId='me',
                                                     id=message['id'], format='metadata').execute()

                for add in msg['payload']['headers']:
                    if add['name'] == "From":
                        # fetching sender's email name
                        a = str(add['value'].split("<")[0])
                        print(a)

                        speak("Email from " + a)
                        text = get_audio()

                        if text == "read":
                            print(msg['snippet'])
                            # speak up the mail
                            speak(msg['snippet'])
                        elif text == "delete":
                            # Delete the email
                            service.users().messages().delete(userId='me', id=message['id']).execute()
                            speak("Email deleted.")
                            print(f"Email from {a} deleted.")
```
Damit diese Variante Funktioniert, müssten wir einmal die Scopes des Projekts
```python
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
```
auf Modify setzen und dann auf Google in unserem Projekt verändern.

![](https://i.imgur.com/OlTGrNi.png)
Leider funktionierte das nicht, da wir uns sonst bei Google hätten verifizieren müssen, damit wir diese Rechte bekommen.
![](https://ii.imgur.com/3f0PPqK.png)
Deswegen haben wir uns dazu entschieden, das Problem erstmal anders anzugehen, indem wir die E-Mails in den Papierkorb verschieben, was keine weiteren Rechte braucht.

#### 3.15.5 Funktion zum Löschen von E-Mails: “move_to_trash”
Um E-Mails zu löschen, wurde die Funktion `move_to_trash()` entwickelt, die E-Mails in den Papierkorb verschiebt. Damit dies Funktioniert muss man die Funktion auch in “Check_mails()” Aufrufen und implementieren.
```python
def move_to_trash(service, email_id):
    """
    Funktion zum Verschieben einer E-Mail in den Papierkorb.

    Args:
        service: Der authentifizierte Gmail-API-Service.
        email_id (str): Die ID der zu löschenden E-Mail.
    """
    try:
        service.users().messages().trash(userId='me', id=email_id).execute()
        print(f"E-Mail mit der ID {email_id} wurde in den Papierkorb verschoben.")
        speak("Nachricht gelöscht und in den Papierkorb verschoben.")
    except Exception as e:
        print(f"Fehler beim Verschieben der E-Mail: {e}")
```

```python
def check_mails(service):
...
elif text == "delete":
                       move_to_trash(service, message['id'])
```
#### 3.15.6 Zwischenschritt
Hier ist uns aufgefallen, dass bei dem Sprachbefehl “Leave” nichts passiert, also haben wir dies schnell implementiert.
```python
if text == "leave":
                           speak("Goodbye!")
                           return
```
#### 3.15.7 Gespräch mit einem Outside Experten (Prof.)
Nach dem Gespräch mit unserem Prof kamen wir zur Einsicht, dass es besser wäre, mit IMAP und SMTP zu arbeiten, anstatt die Google-API zu verwenden.
Der erste Schritt war es also alles zu löschen, das mit der API Verwendung zu tun hatte.
Daraufhin haben wir erstmal IMAP und SMTP Recherchiert.
IMAP ist dafür da um Daten abzurufen und SMTP ist für das senden von Daten da.

#### 3.15.8 IMAP Implementierung mit “def connect_to_email()”
Im Grunde muss man nur eine weitere Funktion im Code definieren, das Verbinden zur E-Mail. Wichtig ist hier, dass man in seinem jeweiligen Email-Account das IMAP Forwarding aktiviert. Wenn man Gmail verwendet, muss man 2-Faktor-Security aktivieren und dann ein App Passwort einrichten.
```python
def connect_to_email():
   """Connect to the email server."""
   email_user = 'jarvis505hsnr@gmail.com'
   email_pass = 'xgkj unvv xbqm bxno'

   # Connect to the IMAP server
   mail = imaplib.IMAP4_SSL('imap.gmail.com')
   mail.login(email_user, email_pass)

   return mail
```
#### 3.15.9 Das löschen von E-Mails - Überarbeitet
Die vorherige Funktion “move_to_trash()” wurde gelöscht und wir haben ein paar neue Zeilen an Code hinzugefügt, da wir nun die Google-Scopes umgehen können
```python
elif text == "delete":
   mail.store(email_id, '+FLAGS', '\\Deleted')
   mail.expunge()
   speak("Email deleted.")
```
## 3.16 Grundgerüst Teil 3
#### 3.16.1 NONE-Sicherheitssystem
Damit die Befehle richitg ausgeüfhrt werden, wurde das folgende Konzept verwendet. Es wird verhindert, dass die Spracheingabe “nichts” (None) zurückgibt.

```python
text = None
while text == None:
    text = get_audio()
```


#### 3.16.2 Chatbot Testversuch mit openai
Für ein grundlegendes Verständnis haben wir ein Chatbot erstellt, 
welches die Openai API nutzt. Dies dient zur Generierung dynamischer Antworten.

```python 
import openai

openai.api_key = "sk-Yv3DJ3A8jKBubhfd9wpFZ7cre7fptVkNIhob04rDoXT3BlbkFJt2RY4QGRR75Ejvx8fd5WOOthvxK59tu4ZQG5JiAa0A"

def chat_with_gpt(prompt):
    gpt_response = openai.ChatCompletion.create(  # Changed 'response' to 'gpt_response'
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}]
    )
    return gpt_response['choices'][0]['message']['content'].strip()

if __name__ == "__main__":
    while True:
        user_input = input("You: ")
        if user_input.lower() in ["quit", "exit", "bye"]:
            break

        try:
            chat_response = chat_with_gpt(user_input)
            print("Chatbot: ", chat_response)
        except openai.error.RateLimitError:
            print("You have exceeded your current quota. Please check your OpenAI plan and billing details.")
            break

```
#### 3.16.3 Nachrichtenausgabe Testversuch mit newsapi
Ebenso sind wir mit der Ausgabe der aktuellen Nachrrichten vorgegangen. Es wurde die NewsAPI zur Abfrage und Ausgabe aktueller Nachrichten genutzt.

```python 
from newsapi import NewsApiClient
import pyttsx3

def get_news():
    newsapi = NewsApiClient(api_key='27b11c408f6e41cdb927b1b3e4943949')  # Hol dir einen API-Schlüssel unter https://newsapi.org/

    top_headlines = newsapi.get_top_headlines(language='en', country='us')

    for article in top_headlines['articles'][:5]:  # Die ersten 5 Artikel vorlesen
        print(article['title'])
        speak(article['title'])
        speak(article['description'])

def speak(text):
    engine = pyttsx3.init()
    engine.say(text)
    engine.runAndWait()

if __name__ == "__main__":
    get_news()
```

#### 3.16.4 Einbettung der Newsapi
Zunächst wurde der funktionierende News API in den bestehenden Code eingebettet. Für die Benutzerfreundlichkeit wurde dann vor der E-Mail eine Zahl geschrieben und eingebaut, dass der Benutzer die Anzahl der angezeigten Nachrichten selbst bestimmen kann. Diese können auf Deutsch und Englisch vorgelesen werden. Um die gesprochene Zahl “vier” in die Zahl “4” zu konvertieren, hat uns Herr Grothe einen Tipp gegeben, die bereits vorhandene Bibliotheken aus Python zu nutzen. Zudem ist hier ebenfalls das NONE-Sicherheitssystem zu erkennen.

```python 
def get_news():
    top_headlines = newsapi.get_top_headlines(language='en', country='us')

    if top_headlines['articles']:
        speak("How many news do you want to hear?")
        count_news = None
        while count_news is None:
            count_news = get_audio("en-EN")
            ##count_news = get_audio("de-DE")
        k = text2num(count_news, "en")
        ##k = text2num(count_news, "de")
        news_text = "Here are {} top news headlines.".format(k)
        print(news_text)
        speak(news_text)
        i = 0
        for article in top_headlines['articles'][:k]:  # Read out the first k articles
            i += 1
            match i:
                case 1:
                    sText = "{}st news: \'{}\'".format(i, article['title'])
                case 2:
                    sText = "{}nd news: \'{}\'".format(i, article['title'])
                case 3:
                    sText = "{}rd news: \'{}\'".format(i, article['title'])
                case _:
                    sText = "{}th news: \'{}\'".format(i, article['title'])
            print(sText)
            speak(sText)
            speak(article['description'])
    else:
        speak("Sorry, I couldn't find any news right now.")
```

#### 3.16.5 Spracherkennung und Ausgabe
Es wurde nun eine Funktion eingebaut, um die richtige Sprache auszugeben und vom Programm zu erkennen.

```python
def speak(text):
    """Convert text to speech."""
    language = detect(text)
    match language:
        case "de":
            index = 0
        case "en":
            index = 1
        case _:
            index = 0

    engine = pyttsx3.init()
    voices = engine.getProperty('voices')
    engine.setProperty('voice', voices[index].id)
    rate = engine.getProperty('rate')
    engine.setProperty('rate', rate - 50)
    engine.say(text)
    engine.runAndWait()
```

#### 3.16.6 Sprache des Systems herrausfinden
Folgend wird gezeigt, wie man die Sprache im Register-Editor herrausffindet:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech\Voices\Tokens\

0 = TTS_MS_DE-DE_HEDDA_11.0
1 = TTS_MS_EN-US_DAVID_11.0
2 = TTS_MS_EN-US_ZIRA_11.0


#### 3.16.7 Spracheingabe beim Aufrufen
Bei der Spracheingabe wird beim Aufrufen angegeben, ob es sich um Deutsch oder Englisch handelt. Entsprechend werden auch die Fehlermeldungen angepasst auf die Sprache.


```python
def get_audio(language="en-US"):
    """
    Get audio input from the user.
    language = "de-DE" --> German
             = "en-EN" --> Englisch
             = "en-US" --> American (Standard)

    Returns:
    str: The text converted from the audio input.
    """
    r = sr.Recognizer()
    said = None
    try:
        with sr.Microphone(device_index=1) as source:
            r.adjust_for_ambient_noise(source, duration=0.5)
            if language == "de-DE":
                print("Bitte jetzt sprechen...")
            else:
                print("Listening...")
            audio = r.listen(source, timeout=5)
            try:
                said = r.recognize_google(audio, language=language, show_all=False)
                if language == "de-DE":
                    print(f"Du sagtest: {said}")
                else:
                    print(f"You said: {said}")
            except sr.UnknownValueError:
                if language == "de-DE":
                    print("Die Spracherkennung von Google konnte Audio nicht verstehen.")
                else:
                    print("Google Speech Recognition could not understand audio.")
            except sr.RequestError as e:
                if language == "de-DE":
                    print(f"Ergebnisse vom Google-Spracherkennungsdienst konnten nicht angefordert werden: {e}")
                else:
                    print(f"Could not request results from Google Speech Recognition service: {e}")
            except sr.WaitTimeoutError:
                if language == "de-DE":
                    print("Zeitüberschreitung beim Abhören.")
                else:
                    print("Listening timed out.")
    except Exception as e:
        if language == "de-DE":
            print(f"Mikrofonfehler: {e}")
        else:
            print(f"microphone error: {e}")
    return said.lower() if said is not None else None
```


#### 3.16.8 Ausgaben Präzision
Diese Funktion soll für die Benutzerfreundlichkeit die Ausgaben verkürzen und präzisieren.

```python
def check_mails(mail):
    """Check and read out emails."""
    mail.select('inbox')
    result, data = mail.search(None, 'ALL')
    email_ids = data[0].split()

    if not email_ids:
        print('No messages found.')
        speak('No messages found.')
        return

    # Reverse the email_ids list to read from newest to oldest
    email_ids = email_ids[::-1]

    print(f"{len(email_ids)} emails found.")
    speak(f"{len(email_ids)} emails found.")
    speak("If you want to read any particular email, just say read.")
    speak("If you want to delete any particular email, just say delete.")
    speak("If you want to skip a particular email, just say skip.")
    speak("And for leaving, say exit.")
    print("Please say read, delete, skip or exit")
    speak("Please say: read, delete, skip, or exit")

```

#### 3.16.9 Globale Variabeln
Nun ist uns aufgefallen, dass wir Variabeln, Funktion unabhängig gebraucht haben, daher haben wir Globale Variablen eingeführt. 

```python
# Initialize NewsApiClient with your API key
newsapi = NewsApiClient(api_key='27b11c408f6e41cdb927b1b3e4943949')

# Login Data
email_user = 'jarvis505hsnr@gmail.com'
email_pass = 'xgkj unvv xbqm bxno'

# Initialize PyAudio
p = pyaudio.PyAudio()
```

Folgend ist zu sehen, dass wir die googleapi gelöscht haben und durch imap ersetzt haben, um die E-mails zu lesen und zu löschen. Zusätzlich ist smtp hinzugefügt worden, um E-Mails zu senden.

```python
def imap_connect_to_email():
    """Connect to the email server."""
    # Connect to the IMAP server
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(email_user, email_pass)

    return mail
```

```python
def smtp_connect_to_email():
    """Connect to the email server."""
    # Connect to the SMTP server
    try:
        smtp_ssl = smtplib.SMTP_SSL(host="smtp.gmail.com", port=465)
    except Exception as e:
        print("ErrorType : {}, Error : {}".format(type(e).__name__, e))
        smtp_ssl = None

    smtp_ssl.login(email_user, email_pass)
    return smtp_ssl
```

```python
def read_email():
    mail = imap_connect_to_email()
    check_mails(mail)
    mail.logout()  # Logout after checking emails
```

#### 3.16.10 Nachrichten zusammenbauen

Um die Nachrichten zusammenzubauen, wurde diese Funktion eingebaut. Die Automation muss jedoch noch eingebaut, durchdacht und diskutiert werden.

```python
def create_mail():
    message = email.message.EmailMessage()
    message["From"] = email_user
    message["To"] = ["Pascal.ng1310@gmail.com"]
    message["cc"] = ["Test1@gmx.de"]
    #message["Bcc"] = ["Test2@gmx.de"]
    message["Subject"] = "Test Email Nr. 2"

    body = '''
    Hallo Pascal,

    das ist ein Test-Email vom Message-Projekt.

    Gruss
    Test-Gruppe
    '''
    message.set_content(body)

    return message
```

```python
def write_email():
    smtp_ssl = smtp_connect_to_email()
    message = create_mail()
    smtp_ssl.send_message(msg=message)
    smtp_ssl.quit()

    sText = "Email to {} is sent with subject: ".format(message["To"])
    print(sText)
    speak(sText)
    print(message["Subject"])
    speak(message["Subject"])
    print("Inhalt:")
    print(message.get_content())
    speak(message.get_content())
```


#### 3.16.11 Chatbot
Ebenfalls wurde dann für ein komplettes Grundgerüst “talk_with_chatgpt” eingefügt. Diese konnte jedoch noch nicht eingefügt werden, da noch nicht klar ist, welchen chatbot bzw. Ai wir nutzen. Liegengelassen wurde dies, da es hier hauptsächlich nur um das Grundgerüst geht und das Konzept für das Gespräch mit Jarvis noch nicht komplett durchdacht ist.

```python
def talk_with_chatgpt():
    print("Die Funktion ist noch offen.")
    speak("Die Funktion ist noch offen.")
```

### 3.17 Kompletter Pythoncode

```python
import os
import smtplib
import imaplib
import email
import pyttsx3
import speech_recognition as sr
import pyaudio
from newsapi import NewsApiClient
from text_to_num import text2num
from langdetect import detect


# Initialize NewsApiClient with your API key
newsapi = NewsApiClient(api_key='27b11c408f6e41cdb927b1b3e4943949')

# Login Data
email_user = 'jarvis505hsnr@gmail.com'
email_pass = 'xgkj unvv xbqm bxno'

# Initialize PyAudio
p = pyaudio.PyAudio()


def speak(text):
    """Convert text to speech."""
    language = detect(text)
    match language:
        case "de":
            index = 0
        case "en":
            index = 1
        case _:
            index = 0

    engine = pyttsx3.init()
    voices = engine.getProperty('voices')
    engine.setProperty('voice', voices[index].id)
    rate = engine.getProperty('rate')
    engine.setProperty('rate', rate - 50)
    engine.say(text)
    engine.runAndWait()


def get_audio(language="en-US"):
    """
    Get audio input from the user.
    language = "de-DE" --> German
             = "en-EN" --> Englisch
             = "en-US" --> American (Standard)

    Returns:
    str: The text converted from the audio input.
    """
    r = sr.Recognizer()
    said = None
    try:
        with sr.Microphone(device_index=1) as source:
            r.adjust_for_ambient_noise(source, duration=0.5)
            if language == "de-DE":
                print("Bitte jetzt sprechen...")
            else:
                print("Listening...")
            audio = r.listen(source, timeout=5)
            try:
                said = r.recognize_google(audio, language=language, show_all=False)
                if language == "de-DE":
                    print(f"Du sagtest: {said}")
                else:
                    print(f"You said: {said}")
            except sr.UnknownValueError:
                if language == "de-DE":
                    print("Die Spracherkennung von Google konnte Audio nicht verstehen.")
                else:
                    print("Google Speech Recognition could not understand audio.")
            except sr.RequestError as e:
                if language == "de-DE":
                    print(f"Ergebnisse vom Google-Spracherkennungsdienst konnten nicht angefordert werden: {e}")
                else:
                    print(f"Could not request results from Google Speech Recognition service: {e}")
            except sr.WaitTimeoutError:
                if language == "de-DE":
                    print("Zeitüberschreitung beim Abhören.")
                else:
                    print("Listening timed out.")
    except Exception as e:
        if language == "de-DE":
            print(f"Mikrofonfehler: {e}")
        else:
            print(f"microphone error: {e}")
    return said.lower() if said is not None else None


def imap_connect_to_email():
    """Connect to the email server."""
    # Connect to the IMAP server
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(email_user, email_pass)

    return mail

def smtp_connect_to_email():
    """Connect to the email server."""
    # Connect to the SMTP server
    try:
        smtp_ssl = smtplib.SMTP_SSL(host="smtp.gmail.com", port=465)
    except Exception as e:
        print("ErrorType : {}, Error : {}".format(type(e).__name__, e))
        smtp_ssl = None

    smtp_ssl.login(email_user, email_pass)
    return smtp_ssl

def check_mails(mail):
    """Check and read out emails."""
    mail.select('inbox')
    result, data = mail.search(None, 'ALL')
    email_ids = data[0].split()

    if not email_ids:
        print('No messages found.')
        speak('No messages found.')
        return

    # Reverse the email_ids list to read from newest to oldest
    email_ids = email_ids[::-1]

    print(f"{len(email_ids)} emails found.")
    speak(f"{len(email_ids)} emails found.")
    speak("If you want to read any particular email, just say read.")
    speak("If you want to delete any particular email, just say delete.")
    speak("If you want to skip a particular email, just say skip.")
    speak("And for leaving, say exit.")
    print("Please say read, delete, skip or exit")
    speak("Please say: read, delete, skip, or exit")

    i = 0
    for email_id in email_ids:
        i = i +1
        result, message_data = mail.fetch(email_id, '(RFC822)')

        # Check if the fetch was successful
        if result != 'OK':
            print("Error fetching email.")
            continue

        # Ensure message_data is in the expected format
        msg = email.message_from_bytes(message_data[0][1]) if isinstance(message_data[0], tuple) and len(
            message_data[0]) > 1 else None

        if msg is None:
            print("Could not parse email message.")
            continue

        match i:
            case 1:
                sText = "{}st ".format(i)
            case 2:
                sText = "{}nd ".format(i)
            case 3:
                sText = "{}rd ".format(i)
            case _:
                sText = "{}th ".format(i)

        sText1 = sText + "Email is From: {}, Subject: {}'".format(msg['From'], msg['Subject'])
        print(sText1)
        sText2 = sText + "Email is from {} with subject: {}'".format(msg['From'], msg['Subject'])
        speak(sText2)
        text = None
        while text == None:
            text = get_audio()

        if text == "exit":
            speak("Goodbye!")
            return

        if "read" in text:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode()
                        print(body)
                        speak(body)
            else:
                body = msg.get_payload(decode=True).decode()
                print(body)
                speak(body)
            print("Would you wand to delete this email? (yes/no)")
            speak("Would you wand to delete this email?")
            speak("Please say yes or no.")
            text_loeschen = None
            while text_loeschen == None:
                text_loeschen = get_audio()
            if "yes" in text_loeschen:
                mail.store(email_id, '+FLAGS', '\\Deleted')
                mail.expunge()
                speak("Email deleted.")

        elif "delete" in text:
            mail.store(email_id, '+FLAGS', '\\Deleted')
            mail.expunge()
            speak("Email deleted.")
        else:
            speak("Email skipped.")


def get_news():
    top_headlines = newsapi.get_top_headlines(language='en', country='us')

    if top_headlines['articles']:
        speak("How many news do you want to hear?")
        count_news = None
        while count_news is None:
            count_news = get_audio("en-EN")
            ##count_news = get_audio("de-DE")
        k = text2num(count_news, "en")
        ##k = text2num(count_news, "de")
        news_text = "Here are {} top news headlines.".format(k)
        print(news_text)
        speak(news_text)
        i = 0
        for article in top_headlines['articles'][:k]:  # Read out the first k articles
            i += 1
            match i:
                case 1:
                    sText = "{}st news: \'{}\'".format(i, article['title'])
                case 2:
                    sText = "{}nd news: \'{}\'".format(i, article['title'])
                case 3:
                    sText = "{}rd news: \'{}\'".format(i, article['title'])
                case _:
                    sText = "{}th news: \'{}\'".format(i, article['title'])
            print(sText)
            speak(sText)
            speak(article['description'])
    else:
        speak("Sorry, I couldn't find any news right now.")


def read_email():
    mail = imap_connect_to_email()
    check_mails(mail)
    mail.logout()  # Logout after checking emails


def talk_with_chatgpt():
    print("Die Funktion ist noch offen.")
    speak("Die Funktion ist noch offen.")


def create_mail():
    message = email.message.EmailMessage()
    message["From"] = email_user
    message["To"] = ["Pascal.ng1310@gmail.com"]
    message["cc"] = ["Test1@gmx.de"]
    #message["Bcc"] = ["Test2@gmx.de"]
    message["Subject"] = "Test Email Nr. 2"

    body = '''
    Hallo Pascal,

    das ist ein Test-Email vom Message-Projekt.

    Gruss
    Test-Gruppe
    '''
    message.set_content(body)

    return message

def write_email():
    smtp_ssl = smtp_connect_to_email()
    message = create_mail()
    smtp_ssl.send_message(msg=message)
    smtp_ssl.quit()

    sText = "Email to {} is sent with subject: ".format(message["To"])
    print(sText)
    speak(sText)
    print(message["Subject"])
    speak(message["Subject"])
    print("Inhalt:")
    print(message.get_content())
    speak(message.get_content())

def main():
    while True:
        speak("Would you like to check your emails, hear the latest news or chat with chatgpt? Or say exit to quit.")
        print("Please say email, news, ChatGPT or exit")
        speak("Please say: email, news, ChatGPT, or exit")
        text = None
        while text == None:
            text = get_audio()

        if text == "exit":
            speak("Goodbye!")
            break

        if "email" in text:
            speak("Do you want to read your emails or write a email?")
            print("Please say read or write")
            speak("Please say read or write")
            answer = None
            while answer == None:
                answer = get_audio()
            if "read" in answer:
                read_email()
            else:
                write_email()
        elif "news" in text:
            get_news()
        elif "gpt" in text:
            talk_with_chatgpt()
        else:
            speak("I didn't understand. Please say email or news.")


if __name__ == "__main__":
    main()
```

# 4 Realisierung (Meilenstein 2)

## 4.1 Verteilungssicht
Technische Infrastruktur mit Umgebungen, Computern, Prozessoren, Topologien.
Zuordnung von (Software-)Bausteinen zu Infrastruktur-Elementen Quelle: ARC42.


## 4.2 Umsetzung

Folgend werden Realisierungsdetails der Softwarekomponenten beschrieben. Es wird erklärt, welche Vorgaben aus der Architektur in den  Softwarekomponenten realisiert wurden. Es werden Drei Softwarekomponenten dargestellt, wobei sich die Email Komponenten in 2 Teilkomponenten aufteilt. Zudem wird als weitere Komponente die Verschlüsselung und das Regestrierungsfester beschrieben im Bezug auf die Umsetzung. Bei allen Komponenten wurde vorher eine Recherche durchgeführt und mit der Gruppe evaluiert, welche Tools wir nutzen und wie wir diese nutzen und implementieren. 

### 4.2.1 Softwarekomponente Chatbot
In diesem code schnipsel bauen wir eine conversation mit der LLM names Gemini auf die von Google ist.

1. Konfiguration
• Richtet Parameter für die Textgenerierung ein, z.b. Temperatur (Steuert ob die AI Kreativ oder eher Stumpf Antwortet), Top-P, Top-K und maximale Ausgabelänge.
• Definiert auch eine Systemanweisung zur Steuerung des Antwort Styles.

2. Modelinitialisierung
• Erstellt eine generative Modellinstanz unter Verwendung des ausgewählten Modells (In unserem Falle Gemini 1.5 Flash-Modell) und unsere Konfiguration.

3. Conversation Loop
• Erhält den User-Input per Spracheingabe.
• Startet eine neue Chat-Sitzung mit dem Modell.
• Druckt und spricht die Antwort des Modells.

Essenziell ermöglicht unser Code dem Benutzer über Sprachbefehle mit der Gemini LLM zu interagieren um textbasierte Antworten zu erhalten, die dann vorgelesen werden.



### 4.2.2 Softwarekomponente News
• Wie wurden die Vorgaben aus der Architektur in der Software Komponente B realisiert

Eine Anforderung von Jarvis war es, dass er uns aktuelle News erzählen kann. Dies haben wir umgesetzt, indem wir uns die```newsapi```-Bibliothek zu nutzen genommen haben. Um die Funktion umzusetzen wird ```get_news()``` genutzt. Über die Funktion```get_audio()``` in Kombination mit```text2num``` kann man per Sprachsteuerung sagen was man möchte und wieviele News man hören möchte. ```k``` ist in dem Fall die Zahl. 
```python
def get_news():
    top_headlines = newsapi.get_top_headlines(language=my_config["news_language"], country=my_config["news_country"])

    if top_headlines['articles']:
        speak("How many news do you want to hear?")
        count_news = None
        while count_news is None:
            count_news = get_audio("en-EN")
            ##count_news = get_audio("de-DE")

        try:
            k = text2num(count_news, "en")
            ##k = text2num(count_news, "de")
        except Exception as e:
            csvlogger.critical("ErrorType : {}, Error : {}".format(type(e).__name__, e))
            print("ErrorType : {}, Error : {}".format(type(e).__name__, e))
            print("All {} messages are output!!!".format(len(top_headlines['articles'])))
            ##k = len(top_headlines['articles'])
            k = 1

        news_text = "Here are {} top news headlines.".format(k)
        print(news_text)
        speak(news_text)
        i = 0
        for article in top_headlines['articles'][:k]:  # Read out the first k articles
            i += 1
            match i:
                case 1:
                    sText = "{}st news: \'{}\'".format(i, article['title'])
                case 2:
                    sText = "{}nd news: \'{}\'".format(i, article['title'])
                case 3:
                    sText = "{}rd news: \'{}\'".format(i, article['title'])
                case _:
                    sText = "{}th news: \'{}\'".format(i, article['title'])
            print(sText)
            speak(sText)
            if article['description'] == None:
                speak("No description. The news ist empty.")
            else:
                speak(article['description'])
    else:
        speak("Sorry, I couldn't find any news right now.")
``` 
1. Nachrichten abrufen
• Holt aktuelle Schlagzeilen von einer Nachrichten-API.

2. Abfrage der News
• Hier wird gefragt, wie viele Nachrichten man hören möchte. 

3. Nachrichten vorlesen
• Titel und Beschreibung der News werden vorgelesen, basierend auf der Anzahl, welche man gesagt hat.

4. Fehlermeldungen
• Wenn es aktuell keine neuen Nachrichten gibt bzw. es keine erkannt worden sind, wird ein Fehler gemeldet. Dasselbe geschieht auch bei fehlerhafter Eingabe.



### 4.2.3 Softwarekomponente Email
Bei der Realisierung der Email erwies sich nach Gesprächen mit Herrn Grothe die bereits implementierte und nahe zu funktionierende GoogleAPI als Fehlentscheidung. 
Die ausschlaggebenden Argumente für die API waren, dass diese einfach und besonders Sicher ist.
Wir sind auf das Problem gestoßen, dass jeder Email provider verschiedene Level an Rechten vergibt. Bei Gmail hatten wir Fall das wir keine E-Mails endgültig löschen konnten und sie nur in den Papierkorb verschieben durften. Daher haben sind wir auf IMAP und SMTP umgestiegen, um E-mails zu versenden, löschen und zu lesen. Hauptgründe um nun wirklich zu wechseln, da wir das endgültige Löschen nicht benötigt haben, sind die Einfachheit und die Unabhängigkeit von E-Mail-Diensten. 

#### 4.2.4 check_mails() und IMAP
Um das Lesen der Emails zu ermöglichen haben wir uns IMAP (Internet Message Access Protocol) zu nutze gemacht um so mit dem IMAP Server unseres Providers zu kommunizieren. 

```python
def imap_connect_to_email():
    """Connect to the email server."""
    # Connect to the IMAP server
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(email_user, email_pass)

    return mail
```

Den Inhalt in "mail" verwenden wir in unserer nächsten Funktion,```check_mails(mail)```
Um unsere Ziele zu erreichen was das Lesen von Emails angeht geht unser code so vor:
1. Verbindet zur Inbox und bekommt die Emails
• Wählt den Inbox Ordner aus.
• Sucht nach allen Emails 'ALL' 
• Dreht die Email ID's um damit die ersten Emails zuerst angezeigt/vorgelesen werden.

2. Loop durch alle Emails
Für jede Email ID:
• Holt sich das Programm alle Email Details
• Analysiert die Email Message
• Kündigt die Email Reihe an (1st, 2nd, 3rd usw.)

3. Liest den Email Text basieren auf den User-Input oder macht andere aktionen.
• Hört auf die Voice commands "read", "delete", "skip" oder "exit"
• Wenn „read“ - Extrahiert den Klartexttext der E-Mail und liest ihn vor. Fragt den Benutzer danach, ob er die E-Mail löschen möchte.
• Bei „delete“: Markiert die E-Mail zum Löschen und entfernt sie vom Server.
• Bei „skip“: Weiter zur nächsten E-Mail.
• Bei „exit“: Beendet das Programm.


#### 4.2.5 schreiben


#### 4.2.6 Regestrierungfenster


#### 4.2.7 Verschlüsselung 



## 4.3 Querschnittliche Konzepte
Gesamthaft wichtige Regelungen und Lösungsansätze, die in mehreren Teilen (→ querschnittlich) des
Systems relevant sind. Konzepte sind oft mit mehreren Bausteinen verbunden. Umfassen verschiedene
Themen wie Domänenmodelle, Architekturmuster und -stile, Regeln für die Verwendung spezifischer
Technologien und Implementierungsregeln Quelle: ARC42.

## 4.4 Testen
• Hier beschreiben Sie die Umsetzung/Realisierung Ihres Testplans.
(Damit man Gmail verwenden kann für unsere Applikation muss man bei Gmail in den Einstellungen IMAP  aktivieren https://support.google.com/a/answer/105694?hl=de .  Außerdem braucht man ein App passwort. Dies kann man leider auch erst nach einer 2 Faktor Sicherung des Google Accounts einrichten.https://knowledge.workspace.google.com/kb/how-to-create-app-passwords-000009237 Dieses App Passwort wird verwendet um in auf den IMAP Server zu zugreifen.)

...

# 5 Anleitungen (Meilenstein 3)

## 5.1 Installationsanleitung

## 5.2 Betreiberdokumentation

# 6 Cross-Grading (Meilenstein 4)

## 6.1 System under Test

## 6.2 Testplan

## 6.3 Installation

## 6.4 Testdurchführung

## 6.5 Fazit

## 6.6 Glossar

# 7 Zusammenfassung und Fazit


