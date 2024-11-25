import tkinter as tk
from tkinter import ttk
from threading import Thread
import time
import pyttsx3


# Funktion für Jarvis' Antwort
def jarvis_reply(user_input):
    # Hier sollte die Logik aus deinem bestehenden Code eingebunden werden
    reply = f"Jarvis: Ich habe '{user_input}' verstanden."  # Placeholder
    return reply


# Animation der Soundwellen
def animate_soundwaves(canvas, is_speaking):
    while is_speaking[0]:
        for i in range(5):
            canvas.create_oval(50 + i*20, 50 + i*20, 150 - i*20, 150 - i*20, outline="blue", width=2)
            time.sleep(0.1)
            canvas.delete("all")
        canvas.update()


# Hauptfunktion, um Nachrichten zu senden
def send_message():
    user_input = user_entry.get()
    if user_input.strip() == "":
        return

    chat_history.config(state=tk.NORMAL)
    chat_history.insert(tk.END, f"You: {user_input}\n")
    chat_history.config(state=tk.DISABLED)
    user_entry.delete(0, tk.END)

    # Jarvis' Antwort
    is_speaking[0] = True
    animation_thread = Thread(target=animate_soundwaves, args=(sound_canvas, is_speaking))
    animation_thread.start()

    response = jarvis_reply(user_input)
    time.sleep(2)  # Simulate processing time
    is_speaking[0] = False

    chat_history.config(state=tk.NORMAL)
    chat_history.insert(tk.END, f"{response}\n")
    chat_history.config(state=tk.DISABLED)


# GUI erstellen
root = tk.Tk()
root.title("Jarvis Chatbox")
root.geometry("600x600")
root.resizable(False, False)

# Chat-Verlauf
chat_frame = tk.Frame(root, bg="white")
chat_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

chat_history = tk.Text(chat_frame, wrap=tk.WORD, state=tk.DISABLED, bg="white", fg="black", font=("Arial", 12))
chat_history.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Eingabebereich
input_frame = tk.Frame(root, bg="lightgray")
input_frame.pack(fill=tk.X)

user_entry = ttk.Entry(input_frame, font=("Arial", 14))
user_entry.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)

send_button = ttk.Button(input_frame, text="Send", command=send_message)
send_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Soundwellen-Anzeige
sound_canvas = tk.Canvas(root, width=200, height=200, bg="lightblue", highlightthickness=0)
sound_canvas.pack(pady=10)

# Animation-Status
is_speaking = [False]

# Haupt-Loop starten
root.mainloop()
