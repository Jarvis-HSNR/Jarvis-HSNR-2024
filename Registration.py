from tkinter import *
import os
import csv

import Datei_Verschluesselung

def clearConsole():
    command = 'clear'
    if os.name in ('nt', 'dos'):  # If Machine is running on Windows, use cls
        command = 'cls'
    os.system(command)

schluessel = "Pascal"
dateiNameCSV = "beispiel.csv"

class Registration:
    # Contructor
    def __init__(self):
        ##clearConsole()  # Bildschirm/Konsole löschen
        
        # Variablen für Tkinter
        self.loginWindow = Tk()
        self.loginWindow.title("Registration")                  # Fenstertitel setzen
        self.loginWindow.geometry("430x350")                    # Fenstergröße setzen
        self.loginWindow.resizable(width=False, height=False)   # Größe des Fensters nicht veränderbar.

        Label(self.loginWindow, text="Registration", bg="springgreen", width="300", height="2", font=("Calibri", 13)).pack()
        Label(self.loginWindow, text="").pack()
        
        # Passwort-Länge-Text und -Eingabefeld erzeugen und auf der GUI anzeigen
        Label(self.loginWindow, text = "First name : ").place(x = 30, y = 80)
        self.firstname = StringVar(self.loginWindow, value=""  )
        self.firstnameE = Entry(self.loginWindow, width = 25, textvariable=self.firstname)
        self.firstnameE.place(x = 140, y = 80)

        Label(self.loginWindow, text = "Last name : ").place(x = 30, y = 110)
        self.lastname = StringVar(self.loginWindow, value="")
        self.lastnameE = Entry(self.loginWindow, width=25, textvariable=self.lastname)
        self.lastnameE.place(x=140, y=110)

        Label(self.loginWindow, text="e-mail address : ").place(x=30, y=140)
        self.email = StringVar(self.loginWindow, value="")
        self.emailE = Entry(self.loginWindow, width=40, textvariable=self.email)
        self.emailE.place(x=140, y=140)

        Label(self.loginWindow, text="Password : ").place(x=30, y=170)
        self.pwd = StringVar(self.loginWindow, value="")
        self.pwdE = Entry(self.loginWindow, show="*", width=40, textvariable=self.pwd)
        self.pwdE.place(x=140, y=170)

        self.encryption = IntVar(self.loginWindow, 1)
        self.encryptionCB = Checkbutton(self.loginWindow, text='Encryption', variable=self.encryption,
                                             onvalue=1, offvalue=0)
        self.encryptionCB.place(x=140, y=200)

        self.finish = Button(self.loginWindow, text="Finish", width=10, height=1, bg="cyan", command=self.loginWindow.destroy)
        self.finish.place(x = 60, y = 260)

        self.register = Button(self.loginWindow, text="Register", width=20, height=1, bg="cyan", command=self.__save_data)
        self.register.place(x = 200, y = 260)
        self.register["state"] = DISABLED

        def __my_upd(*args):
            if (len(self.firstname.get()) < 1 or len(self.lastname.get()) < 1 or
                    len(self.email.get()) < 1 or len(self.pwd.get()) < 1):
                self.register["state"] = DISABLED
            else:
                self.register["state"] = NORMAL

        self.firstname.trace('w', __my_upd)
        self.lastname.trace('w', __my_upd)
        self.email.trace('w', __my_upd)
        self.pwd.trace('w', __my_upd)

    def __save_data(self):
        #clearConsole()          # Bildschirm/Konsole löschen
        print("Daten gespeichert.")
        print(self.firstname.get())
        print(self.lastname.get())
        print(self.email.get())
        print(self.pwd.get())

        fieldnames = ['First name', 'Last name', 'User', 'Password', 'API_Key']
        data = {}
        data['First name'] = self.firstname.get()
        data['Last name'] = self.lastname.get()
        data['User'] = self.email.get()
        data['Password'] = self.pwd.get()
        data['API_Key'] = '27b11c408f6e41cdb927b1b3e4943949'
        with open(dateiNameCSV, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames, delimiter=';')
            writer.writeheader()
            writer.writerow(data)

        if (self.encryption.get() == 1):
            verschluesseler = Datei_Verschluesselung.DateiVerschluesseler()
            gehashter_schluessel = verschluesseler.schluesselErzeugen(schluessel)
            verschluesseler.dateiVerschluesseln(gehashter_schluessel, dateiNameCSV)

    def run(self):
        self.loginWindow.mainloop()

        
        
if __name__ == "__main__":
    loginTk = Registration()
    loginTk.run()