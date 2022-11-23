import tkinter as tk
from tkinter import ttk
import random
import sqlite3
from datetime import date
import base64
from PIL import ImageTk, Image
import pyperclip
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

version = "1.0.0"
root = tk.Tk()
root.geometry('500x800')
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
        tk.Label(showPwd, text="Website", font=font).grid(row=8, column=1)
        tk.Label(showPwd, text="Password", font=font).grid(row=8, column=2)
        tk.Label(showPwd, text="Last update", font=font).grid(row=8, column=3)

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
            
            tk.Button(showPwd, text=f"{i[0]}", bg=bg, width=17, command=lambda pwd=pwd: pyperclip.copy(pwd)).grid(row=dataRow, column=1)
            #Password - Lambda -> Copy password to clipboard
            tk.Label(showPwd, text=f"{pwd}", bg=bg, width=17).grid(row=dataRow, column=2)
            #Date
            tk.Label(showPwd, text=f"{i[2]}", width=17).grid(row=dataRow, column=3)
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
font='Arial 16 bold'

#User information frame
userInfo = ttk.LabelFrame(root, text='User information')
userInfo.grid(column=0, row=0, padx=50, pady=30)

#User field
tk.Label(userInfo, text="Username:", font=font).grid(row=0, column=1)
userEntry = tk.Entry(userInfo)
userEntry.grid(row=0, column=2, columnspan=1)

#Cipher key
tk.Label(userInfo, text="Cipher key:", font=font).grid(row=1, column=1)
keyEntry = tk.Entry(userInfo, width=20)
keyEntry.grid(row=1, column=2, columnspan=1)

Image_1=Image.open('user.png')
Image_1=Image_1.resize((58,58))
Image_1=ImageTk.PhotoImage(Image_1)
tk.Label(userInfo, image=Image_1, width=140).grid(row=0, column=3, rowspan=3)
 

#Save/Update field
newPwd = ttk.LabelFrame(root, text='Save/Update password')
newPwd.grid(column=0, row=1, padx=20, pady=20)

#Website entry
tk.Label(newPwd, text="Website:", font=font).grid(row=1, column=1)
domainEntry = tk.Entry(newPwd)
domainEntry.grid(row = 1, column = 2)

#Password entry
tk.Label(newPwd, text="Password:", font=font).grid(row=2, column=1)    
pwdEntry = tk.Entry(newPwd)
pwdEntry.grid(row = 2, column = 2)

Image_2=Image.open('key.png')
Image_2=Image_2.resize((58,50))
Image_2=ImageTk.PhotoImage(Image_2)
tk.Label(newPwd, image=Image_2, width=120).grid(row=1, column=3, rowspan=2)

#Save btn
saveBtn = tk.Button(newPwd, text="Save", width=17, height=3, command=save)
saveBtn.grid(row = 3, column = 2, rowspan=1)

#Random btn
randPwd = tk.Button(newPwd, text="Random\n Password", height=3, width=17, command=rand)
randPwd.grid(row = 3, column = 1, rowspan=1)

#Password list field
showPwd = ttk.LabelFrame(root, text='Password list')
showPwd.grid(column=0, row=2, padx=20, pady=20)

#Show btn
showBtn = tk.Button(newPwd, text="Show all", width=17, height=3, command=show)
showBtn.grid(row = 3, column = 3, rowspan=2)

root.mainloop()