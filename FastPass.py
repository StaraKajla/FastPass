import tkinter as tk
import random
import sqlite3
from datetime import date
import base64
import pyperclip
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

version = "1.0.0"
root = tk.Tk()
root.geometry('430x800')
root.title(f"Password manager v{version}")
currentDate = (date.today()).strftime("%B %d, %Y")

def createDb():
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        print("Database created and Successfully Connected to SQLite")
        sqlite_select_Query = "select sqlite_version();"
        cursor.execute(sqlite_select_Query)
        record = cursor.fetchall()
        print("SQLite Database Version is: ", record)

        sqlite_create_table_query = '''CREATE TABLE users (
                                    id INTEGER PRIMARY KEY,
                                    website TEXT NOT NULL,
                                    password TEXT NOT NULL,
                                    creation_date TEXT NOT NULL);'''

        cursor.execute(sqlite_create_table_query)
        connection.commit()

        cursor.close()

    except sqlite3.Error as error:
        print("Error while connecting to sqlite", error)

    finally:
        if connection:
            connection.close()
            print("The SQLite connection is closed")


def save():
    inpPwd = pwdEntry.get()
    inpDom = domainEntry.get()
    inpKey = keyEntry.get()
    
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        print("Successfully connected to databse.")

        ciphertextBase64 = aesCbcPbkdf2EncryptToBase64(inpKey, inpPwd)

        sqlite_search_query = "SELECT website FROM users;"
        cursor.execute(sqlite_search_query)
        data = cursor.fetchall()

        #Check if entry for website already exists and update if it does.
        counter = 0
        exists = False
        for i in data:
            website = str(i[0])
            if inpDom.lower() == website.lower():
                sqlite_update_query = f"UPDATE users SET password='{ciphertextBase64}' WHERE website='{website}';"
                cursor.execute(sqlite_update_query)
                connection.commit()
                exists = True
            counter += 1
                
        #Else crate new entry
        if exists == False:
            sqlite_insert_query = f"INSERT INTO users(website, password, creation_date) VALUES ('{inpDom}','{ciphertextBase64}', '{currentDate}');"
            cursor.execute(sqlite_insert_query)
            connection.commit()
            print(f"INFO: {inpDom}, {ciphertextBase64}, ({currentDate}) - ADDED TO DATABASE")

        pwdEntry.delete(0, "end")
        domainEntry.delete(0, "end")
        show()

        cursor.close()

    except sqlite3.Error as error:
        print("Error while connecting to sqlite", error)

    finally:
        if connection:
            connection.close()
            print("The SQLite connection is closed")

#Create random password
def rand():
    pwdEntry.delete(0, "end")
    chars = "0123456789abcdefghijklmnopqrstuvzywABCDEFGHIJKLMNOPQRstuvzyw!#$%&/.,-*"
    length = 16
    randPwd = "".join(random.sample(chars, length))
    pwdEntry.insert(1, f"{randPwd}")

def show():
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        print("Successfully connected to databse.")
        
        sqlite_data_query = "SELECT website, password, creation_date FROM users"
        cursor.execute(sqlite_data_query)
        data = cursor.fetchall()

        #Display labels
        tk.Label(root, text="Website", font=font).grid(row=8, column=1)
        tk.Label(root, text="Password", font=font).grid(row=8, column=2)
        tk.Label(root, text="Last update", font=font).grid(row=8, column=3)

        #Set Row start location for data display
        dataRow = 10
        counter = 0
        #Set different BG color for visibility reasons
        for i in data:
            bg = 'white'
            if counter % 2 == 0:
                bg = 'light gray'
            #Website
            
            #Call encrypted password and decrypt
            inpKey = keyEntry.get()
            pwd = decrypt(inpKey, i[1])
            
            tk.Button(root, text=f"{i[0]}", bg=bg, width=17, command=lambda pwd=pwd: pyperclip.copy(pwd)).grid(row=dataRow, column=1)
            #Password - Lambda -> Copy password to clipboard
            tk.Label(root, text=f"{pwd}", bg=bg, width=17).grid(row=dataRow, column=2)
            #Date
            tk.Label(root, text=f"{i[2]}", width=17).grid(row=dataRow, column=3)
            dataRow += 1
            counter += 1

        #TODO Create HIDE button functionality
        #tk.Button(root, text="Hide", width=17).grid(row=(dataRow+1), column=2)

        cursor.close()

    except sqlite3.Error as error:
        print("Error while connecting to sqlite", error)

    finally:
        if connection:
            connection.close()
            print("The SQLite connection is closed")

def decrypt(Key, Password):
    try:
        decryptedtext = aesCbcPbkdf2DecryptFromBase64(Key, Password)
        print(decryptedtext)
        return decryptedtext

    except ValueError:
        return ""

def base64Encoding(input):
    dataBase64 = base64.b64encode(input)
    dataBase64P = dataBase64.decode("UTF-8")
    return dataBase64P

def base64Decoding(input):
    return base64.decodebytes(input.encode("ascii"))

def generateSalt32Byte():
    return get_random_bytes(32)

def aesCbcPbkdf2EncryptToBase64(password, plaintext):
    passwordBytes = password.encode("ascii")
    salt = generateSalt32Byte()
    PBKDF2_ITERATIONS = 15000
    encryptionKey = PBKDF2(passwordBytes, salt, 32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
    cipher = AES.new(encryptionKey, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode("ascii"), AES.block_size))
    ivBase64 = base64Encoding(cipher.iv)
    saltBase64 = base64Encoding(salt)
    ciphertextBase64 = base64Encoding(ciphertext)
    return saltBase64 + ":" + ivBase64 + ":" + ciphertextBase64

def aesCbcPbkdf2DecryptFromBase64(password, ciphertextBase64): 
    passwordBytes = password.encode("ascii")
    data = ciphertextBase64.split(":")
    salt = base64Decoding(data[0])
    iv = base64Decoding(data[1])
    ciphertext = base64Decoding(data[2])
    PBKDF2_ITERATIONS = 15000
    decryptionKey = PBKDF2(passwordBytes, salt, 32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
    cipher = AES.new(decryptionKey, AES.MODE_CBC, iv)
    decryptedtext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    decryptedtextP = decryptedtext.decode("UTF-8")
    return decryptedtextP

#Create database
createDb()

#Bold font
font='Helvetica 16 bold'

#User field
tk.Label(text="Username:", font=font).grid(row=0, column=1)
userEntry = tk.Entry(root)
userEntry.grid(row=0, column=2)

#Domain field
tk.Label(text="Website:", font=font).grid(row=1, column=1)
domainEntry = tk.Entry(root)
domainEntry.grid(row = 1, column = 2)

#Password field
tk.Label(text="Password:", font=font).grid(row=2, column=1)    
pwdEntry = tk.Entry(root)
pwdEntry.grid(row = 2, column = 2)

#Save btn
saveBtn = tk.Button(root, text="Save", width=17, height=3, command=save)
saveBtn.grid(row = 3, column = 2, rowspan=2)

#Random btn
randPwd = tk.Button(root, text="Random\n Password", height=3, width=17, command=rand)
randPwd.grid(row = 3, column = 1, rowspan=2)

#Show btn
showBtn = tk.Button(root, text="Show all", width=17, height=3, command=show)
showBtn.grid(row = 3, column = 3, rowspan=2)

tk.Label(text="Info", font=font, width=12).grid(row=0, column=3)
tk.Label(text="Click on password to copy", justify='left', anchor='w').grid(row=1, column=3)
tk.Label(text="Made by WIXO.").grid(row=2, column=3)
#tk.Label(text=f"Version: {version}").grid(row=3, column=3)


tk.Label(root, text="").grid(row=5)
tk.Label(root, text="Cipher key:", font=font).grid(row=6, column=1)
keyEntry = tk.Entry(root, width=40, bg="lightgreen")
keyEntry.grid(row=6, column=2, columnspan=2)
tk.Label(root, text="").grid(row=7)

root.mainloop()