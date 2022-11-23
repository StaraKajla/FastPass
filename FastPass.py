import tkinter as tk
from tkinter import ttk
import tkinter.messagebox
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
root.configure(background="#ffffff")
#Width*Height
root.geometry('530x800')
root.title(f"FastPass v{version}")
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
                                    username TEXT NOT NULL);'''
        
        cursor.execute(sqlite_create_table_query)
        connection.commit()

        sqlite_create_table_query = '''CREATE TABLE passwords (
                                    id INTEGER PRIMARY KEY,
                                    user_id INTEGER,
                                    website TEXT NOT NULL,
                                    password TEXT NOT NULL,
                                    creation_date TEXT NOT NULL,
                                    FOREIGN KEY(user_id) REFERENCES users(user_id));'''

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
    inpUser = userEntry.get()
    if inpUser == "":
        tk.messagebox.showwarning(title="Select user!", message=f"Username can't be empty!")
        return
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        print("Successfully connected to databse.")

        ciphertextBase64 = aesCbcPbkdf2EncryptToBase64(inpKey, inpPwd)

        sqlite_search_query = f"SELECT id FROM users WHERE username='{inpUser}';"
        cursor.execute(sqlite_search_query)
        data = None

        data = cursor.fetchall()
        if data != None:
            uid = data[0][0]

        sqlite_search_query = f"SELECT website FROM passwords WHERE user_id='{uid}';"
        cursor.execute(sqlite_search_query)
        data = cursor.fetchall()

        #Check if entry for website already exists and update if it does.
        exists = False
        for i in data:
            website = str(i[0])
            if inpDom.lower() == website.lower():
                sqlite_update_query = f'''UPDATE passwords SET password='{ciphertextBase64}' 
                                          WHERE website='{website}' AND user_id='{uid}';'''
                cursor.execute(sqlite_update_query)
                connection.commit()
                exists = True
                
        #Else crate new entry
        if exists == False:
            sqlite_insert_query = f'''INSERT INTO passwords(user_id, website, password, creation_date) 
                                      VALUES ('{uid}','{inpDom}','{ciphertextBase64}','{currentDate}');'''
            cursor.execute(sqlite_insert_query)
            connection.commit()

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
        for widget in showPwd.winfo_children():
            widget.destroy()
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        print("Successfully connected to databse.")

        username = userEntry.get()
        if username == "":
            tk.messagebox.showwarning(title="Select user!", message=f"Username can't be empty!")
            return

        sqlite_data_query = f'''SELECT website, password, creation_date FROM passwords WHERE user_id = (
                                SELECT id FROM users where username ="{username}");'''
        cursor.execute(sqlite_data_query)
        data = cursor.fetchall()

        #Display labels
        tk.Label(showPwd, text="Website", font=font).grid(row=0, column=1, padx=10, pady=5)
        tk.Label(showPwd, text="Password", font=font).grid(row=0, column=2, padx=10, pady=5)
        tk.Label(showPwd, text="Last update", font=font).grid(row=0, column=3, padx=10, pady=5)

        #Set Row start location for data display
        dataRow = 1
        counter = 0
        inpKey = keyEntry.get()

        for i in data:            
            pwd = decrypt(inpKey, i[1])
            tk.Button(showPwd, text=f"{i[0]}", width=15, bg=blue, foreground=white, cursor="hand2", 
            command=lambda pwd=pwd: pyperclip.copy(pwd)).grid(row=dataRow, column=1, padx=18, pady=2)
            tk.Label(showPwd, text=f"{pwd}", width=15).grid(row=dataRow, column=2)
            tk.Label(showPwd, text=f"{i[2]}", width=15).grid(row=dataRow, column=3)
            tk.Button(showPwd, text="X", bg="red").grid(row=dataRow, column=4)
            dataRow += 1
            counter += 1

        cursor.close()

    except sqlite3.Error as error:
        print("Error while connecting to sqlite", error)

    finally:
        if connection:
            connection.close()
            print("The SQLite connection is closed")

#TODO: Figure out how to create delete function.
"""def deletePassword(website):
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        print("Successfully connected to databse.")
        username = userEntry.get()

        sqlite_delete_query = f'''DELETE FROM passwords WHERE website="{website}" AND user_id=(
                                  SELECT id FROM users WHERE username="{username}");'''
        print(sqlite_delete_query)
        cursor.execute(sqlite_delete_query)
        connection.commit()

    except sqlite3.Error as error:
        print("Error while connecting to sqlite", error)

    finally:
        if connection:
            connection.close()
            print("The SQLite connection is closed")"""

def addUser():
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        print("Successfully connected to databse.")
        username = userEntry.get()

        if username == "":
            tk.messagebox.showwarning(title="Error", message=f"Username can't be empty!")
            return

        sqlite_data_query = f"SELECT username FROM users;"
        cursor.execute(sqlite_data_query)
        data = cursor.fetchall()
        
        for i in data:
            if i[0] == username:
                tk.messagebox.showwarning(title="Username error", message=f"{username} already exists!")
                return

        sqlite_data_query = f"INSERT INTO users(username) VALUES ('{username}');"
        cursor.execute(sqlite_data_query)
        connection.commit()
        print("Success")
        tk.messagebox.showinfo(title="Success!", message=f"Username: '{username}' successfully added to the database!")           

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

#Color pallet
blue = "#1f63e0"
white = "#ffffff"

#User information frame
userInfo = ttk.LabelFrame(root, text='User information')
userInfo.grid(column=0, row=0, padx=50, pady=10)

#User field
tk.Label(userInfo, text="Username:", font=font, pady=5, padx=25).grid(row=0, column=1)
userEntry = tk.Entry(userInfo)
userEntry.grid(row=0, column=2, columnspan=1)

#Cipher key
tk.Label(userInfo, text="Cipher key:", font=font, pady=10).grid(row=1, column=1)
keyEntry = tk.Entry(userInfo, width=20)
keyEntry.grid(row=1, column=2, columnspan=1)

Image_1=Image.open('user1.png')
Image_1=Image_1.resize((58,58))
Image_1=ImageTk.PhotoImage(Image_1)
btn1 = tk.Button(userInfo, image=Image_1, height=60, width=60, command=addUser, cursor="hand2")
btn1.grid(row=0, column=3, rowspan=2)
tk.Label(userInfo, text="", width=20).grid(row=3, column=3)
 

#Save/Update frame
newPwd = ttk.LabelFrame(root, text='Save/Update password')
newPwd.grid(column=0, row=1, padx=50, pady=10)

#Website entry
tk.Label(newPwd, text="Website:", font=font, pady=5, padx=20).grid(row=1, column=1)
domainEntry = tk.Entry(newPwd)
domainEntry.grid(row = 1, column = 2, pady=5, padx=25)

#Password entry
tk.Label(newPwd, text="Password:", font=font).grid(row=2, column=1)    
pwdEntry = tk.Entry(newPwd)
pwdEntry.grid(row = 2, column = 2)

Image_2=Image.open('key.png')
Image_2=Image_2.resize((58,50))
Image_2=ImageTk.PhotoImage(Image_2)
tk.Label(newPwd, image=Image_2, width=120).grid(row=1, column=3, rowspan=2)

#Save btn
saveBtn = tk.Button(newPwd, text="Save", width=14, height=2, command=save, bg=blue, foreground=white, cursor="hand2")
saveBtn.grid(row = 3, column = 2, rowspan=1, pady=10)

#Random btn
randPwd = tk.Button(newPwd, text="Random\n Password", height=2, width=14, command=rand, bg=blue, foreground=white, cursor="hand2")
randPwd.grid(row = 3, column = 1, rowspan=1)

#Password list field
showPwd = ttk.LabelFrame(root, text='Password list')
showPwd.grid(column=0, row=2, padx=20, pady=20)

#Show btn
showBtn = tk.Button(newPwd, text="Show all", width=14, height=2, command=show, bg=blue, foreground=white, cursor="hand2")
showBtn.grid(row = 3, column = 3, rowspan=2)

root.mainloop()
