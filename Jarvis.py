import os
import csv
import smtplib
import imaplib
import email
import pyttsx3
import speech_recognition as sr
import pyaudio
import configparser
import logging
import google.generativeai as genai

from csv_logger import CsvLogger
from newsapi import NewsApiClient
from text_to_num import text2num
from langdetect import detect

import Registration_Lib
import Datei_Verschluesselung_Lib

# Initialize NewsApiClient with your API key
newsapi = None
model = None

# Login Data
email_user = ''
email_pass = ''

my_config = {}
csvlogger = None

# Initialize PyAudio
p = pyaudio.PyAudio()


def talk_with_gemini():
    """Interact with the Google Gemini AI."""
    speak("What do you want to ask Gemini?")
    user_input = get_audio()  # Hole Benutzereingabe

    if user_input:
        chat_session = model.start_chat(history=[])

        # Sende die Benutzeranfrage an Gemini
        response = chat_session.send_message(user_input)

        # Ausgabe der Antwort
        print(response.text)
        speak(response.text)
    else:
        speak("I didn't hear anything.")

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
    engine.setProperty('rate', rate - int(my_config["default_delay"]))
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
        ##with sr.Microphone(device_index=1) as source:
        with sr.Microphone(device_index=int(my_config["Microphone_device_index"])) as source:
            r.adjust_for_ambient_noise(source, duration=float(my_config["Microphone_duration"]))
            if language == "de-DE":
                print("Bitte jetzt sprechen...")
            else:
                print("Listening...")
            audio = r.listen(source, timeout=int(my_config["Microphone_timeout"]))
            try:
                said = r.recognize_google(audio, language=language, show_all=False)
                if language == "de-DE":
                    print(f"Du sagtest: {said}")
                else:
                    print(f"You said: {said}")
            except sr.UnknownValueError:
                csvlogger.warning('Google Speech Recognition could not understand audio.')
                if language == "de-DE":
                    print("Die Spracherkennung von Google konnte Audio nicht verstehen.")
                else:
                    print("Google Speech Recognition could not understand audio.")
            except sr.RequestError as e:
                csvlogger.error(f"Could not request results from Google Speech Recognition service: {e}")
                if language == "de-DE":
                    print(f"Ergebnisse vom Google-Spracherkennungsdienst konnten nicht angefordert werden: {e}")
                else:
                    print(f"Could not request results from Google Speech Recognition service: {e}")
            except sr.WaitTimeoutError:
                csvlogger.error('Listening timed out.')
                if language == "de-DE":
                    print("Zeitüberschreitung beim Abhören.")
                else:
                    print("Listening timed out.")
    except Exception as e:
        csvlogger.critical(f"microphone error: {e}")
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
        smtp_ssl = smtplib.SMTP_SSL(host=my_config["smtp_host"], port=int(my_config["smtp_port"]))
    except Exception as e:
        csvlogger.critical("ErrorType : {}, Error : {}".format(type(e).__name__, e))
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
        i = i + 1
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
            k = len(top_headlines['articles'])
            ##k = 1

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


def read_email():
    mail = imap_connect_to_email()
    check_mails(mail)
    mail.logout()  # Logout after checking emails


def create_mail():
    message = email.message.EmailMessage()
    message["From"] = email_user

    print("Please say the subject of your email.")
    speak("Please say the subject of your email.")
    text = None
    while text == None:
        text = get_audio()
    message["Subject"] = text
    print("Your subject is \'{}\'".format(message["Subject"]))
    speak(message["Subject"])

    print("Please say your message.")
    speak("Please say your message.")
    text = None
    while text == None:
        text = get_audio()
    body = text
    message.set_content(body)
    print("Your message is \'{}\'".format(body))
    speak(body)

    print("Please enter the To email addresses. The emails should be separated by commas.")
    speak("Please enter the To email addresses. The emails should be separated by commas.")
    message["To"] = input("To: ")

    print("Please enter the cc email addresses. The emails should be separated by commas.")
    speak("Please enter the cc email addresses. The emails should be separated by commas.")
    message["cc"] = input("cc: ")

    print("Please enter the Bcc email addresses. The emails should be separated by commas.")
    speak("Please enter the Bcc email addresses. The emails should be separated by commas.")
    message["Bcc"] = input("Bcc: ")

    return message

def write_email():
    smtp_ssl = smtp_connect_to_email()
    message = create_mail()
    smtp_ssl.send_message(msg=message)
    smtp_ssl.quit()

    sText = "Email to {} is sent with subject: ".format(message["To"])
    print(sText)
    speak(sText)

    if (message["cc"] != ''):
        sText = "Email as copy {} is sent with subject: ".format(message["cc"])
        print(sText)
        speak(sText)

    if (message["Bcc"] != ''):
        sText = "Email as blind copy {} is sent with subject: ".format(message["Bcc"])
        print(sText)
        speak(sText)

    print(message["Subject"])
    speak(message["Subject"])
    print("Inhalt:")
    print(message.get_content())
    speak(message.get_content())

def get_config():
    global my_config

    config = configparser.ConfigParser()
    config.read('config.ini')

    my_config["log_filename"] = config.get('Logging', 'Filename')
    my_config["log_delimiter"] = config.get('Logging', 'Delimiter')
    my_config["log_level"] = config.get('Logging', 'Level')
    my_config["log_max_size"] = config.get('Logging', 'Max_size')
    my_config["log_max_files"] = config.get('Logging', 'Max_files')


    my_config["news_language"] = config.get('News', 'Language')
    my_config["news_country"] = config.get('News', 'Country')

    my_config["default_delay"] = config.get('Default', 'Delay')

    my_config["Microphone_device_index"] = config.get('Microphone', 'device_index')
    my_config["Microphone_duration"] = config.get('Microphone', 'duration')
    my_config["Microphone_timeout"] = config.get('Microphone', 'timeout')

    my_config["smtp_host"] = config.get('SMTP', 'Host')
    my_config["smtp_port"] = config.get('SMTP', 'Port')

    my_config["GenAI_model_name"] = config.get('GenAI', 'model_name')
    my_config["GenAI_temperature"] = config.get('GenAI', 'temperature')
    my_config["GenAI_top_p"] = config.get('GenAI', 'top_p')
    my_config["GenAI_top_k"] = config.get('GenAI', 'top_k')
    my_config["GenAI_max_output_tokens"] = config.get('GenAI', 'max_output_tokens')
    my_config["GenAI_response_mime_type"] = config.get('GenAI', 'response_mime_type')

def init_logging():
    filename = my_config["log_filename"]
    delimiter = my_config["log_delimiter"]
    max_size = int(my_config["log_max_size"])
    max_files = int(my_config["log_max_files"])
    match my_config["log_level"]:
        case "DEBUG":
            level = logging.DEBUG
        case "INFO":
            level = logging.INFO
        case "WARNING":
            level = logging.WARNING
        case "ERROR":
            level = logging.ERROR
        case "CRITICAL":
            level = logging.CRITICAL
        case _:
            level = logging.DEBUG

    custom_additional_levels = ['logs_a', 'logs_b', 'logs_c']
    fmt = f'%(asctime)s{delimiter}%(levelname)s{delimiter}%(message)s'
    datefmt = '%Y/%m/%d %H:%M:%S'
    header = ['Date Time', 'Level', 'Message']

    # Creat logger with csv rotating handler
    csvlogger = CsvLogger(filename=filename,
                          delimiter=delimiter,
                          level=level,
                          add_level_names=custom_additional_levels,
                          add_level_nums=None,
                          fmt=fmt,
                          datefmt=datefmt,
                          max_size=max_size,
                          max_files=max_files,
                          header=header)
    return csvlogger

def get_data():
    global email_user
    global email_pass
    global newsapi
    global model

    schluessel = "Pascal"
    dateipfad = "Geheimdaten.csv"
    newsApiKey = ""


    verschluesseler = Datei_Verschluesselung_Lib.DateiVerschluesseler()
    gehashter_schluessel = verschluesseler.schluesselErzeugen(schluessel)

    verschluesseler.dateiEntschluesseln(gehashter_schluessel, dateipfad)
    with open(dateipfad) as csvdatei:
        csv_reader_object = csv.DictReader(csvdatei, delimiter=';')
        for row in csv_reader_object:
            ###print(row)
            email_user = row["User"]
            email_pass = row["Password"]
            newsApiKey = row["NewsAPI_Key"]
            genaiApiKey = row["GenaiAPI_Key"]

    newsapi = NewsApiClient(api_key=newsApiKey)

    genai.configure(api_key=genaiApiKey)

    generation_config = {
        "temperature": int(my_config["GenAI_temperature"]),
        "top_p": float(my_config["GenAI_top_p"]),
        "top_k": int(my_config["GenAI_top_k"]),
        "max_output_tokens": int(my_config["GenAI_max_output_tokens"]),
        "response_mime_type": my_config["GenAI_response_mime_type"],
    }
    model = genai.GenerativeModel(
        model_name=my_config["GenAI_model_name"],
        generation_config=generation_config,
        system_instruction="You are Jarvis, a Voice Assistant and you can help us answer questions. You only give short answers.",
    )

    verschluesseler.dateiVerschluesseln(gehashter_schluessel, dateipfad)

def main():
    get_config()
    global csvlogger
    csvlogger = init_logging()
    get_data()

    RegTk = Registration_Lib.Registration()
    RegTk.run()

    while True:
        speak("Would you like to check your emails, hear the latest news or chat with Gemini? Or say exit to quit.")
        print("Please say email, news, Gemini or exit")
        speak("Please say: email, news, Gemini, or exit")
        text = None
        while text == None:
            text = get_audio()

        if text == "exit":
            csvlogger.info('Goodbye. THE END.')
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
                csvlogger.info('Read email.')
                read_email()
            else:
                csvlogger.info('Write email.')
                write_email()
        elif "news" in text:
            csvlogger.info('Get news.')
            get_news()
        elif "gemini" in text:
            csvlogger.info('Talk with Gemini.')
            talk_with_gemini()
        else:
            csvlogger.warning("I didn't understand. Please say email, news, Gemini or exit.")
            speak("I didn't understand. Please say email, news, Gemini, or exit.")

if __name__ == "__main__":
    main()