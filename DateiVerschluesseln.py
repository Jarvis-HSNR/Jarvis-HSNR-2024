import Datei_Verschluesselung

def main():
    schluessel = "Pascal"
    dateipfad = "Geheimdaten.csv"
    #dateipfad = "beispiel.csv"

    verschluesseler = Datei_Verschluesselung.DateiVerschluesseler()
    gehashter_schluessel = verschluesseler.schluesselErzeugen(schluessel)
    while True:
        print("1. Datei verschlüsseln")
        print("2. Datei entschlüsseln")
        print("3. Beenden")
        auswahl = input("Bitte Option auswählen : ")
        match auswahl:
            case "1":
                verschluesseler.dateiVerschluesseln(gehashter_schluessel, dateipfad)
            case "2":
                verschluesseler.dateiEntschluesseln(gehashter_schluessel, dateipfad)
            case "3":
                break
            case _:
                print("Falsche Eingabe.....")

if __name__ == "__main__":
    main()