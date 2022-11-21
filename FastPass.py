import tkinter as tk
import random
import sqlite3
from datetime import date
import pyperclip

version = "1.0.0"
root = tk.Tk()
root.geometry('425x400')
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
    
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        print("Successfully connected to databse.")


        sqlite_search_query = "SELECT website FROM users;"
        cursor.execute(sqlite_search_query)
        data = cursor.fetchall()

        #Check if entry for website already exists and update if it does.
        counter = 0
        exists = False
        for i in data:
            website = str(i[0])
            if inpDom.lower() in website.lower():
                sqlite_update_query = f"UPDATE users SET password='{inpPwd}' WHERE website='{website}';"
                cursor.execute(sqlite_update_query)
                connection.commit()
                exists = True
            counter += 1
                
        #Else crate new entry
        if exists == False:
            sqlite_insert_query = f"INSERT INTO users(website, password, creation_date) VALUES ('{inpDom}', '{inpPwd}', '{currentDate}');"
            cursor.execute(sqlite_insert_query)
            connection.commit()
            print(f"INFO: {inpDom}, {inpPwd}, ({currentDate}) - ADDED TO DATABASE")

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
        tk.Label(root, text="Site/User", font=font).grid(row=5, column=1)
        tk.Label(root, text="Password", font=font).grid(row=5, column=2)
        tk.Label(root, text="Last update", font=font).grid(row=5, column=3)

        #Set Row start location for data display
        dataRow = 6
        counter = 0
        #Set different BG color for visibility reasons
        for i in data:
            bg = 'white'
            if counter % 2 == 0:
                bg = 'light gray'
            #Website
            tk.Label(root, text=f"{i[0]}", bg=bg, width=17).grid(row=dataRow, column=1)
            #Password - Lambda -> Copy password to clipboard
            tk.Button(root, text=f"{i[1]}", bg=bg, width=17, command=lambda pwd=i[1]: pyperclip.copy(pwd)).grid(row=dataRow, column=2)
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

#Create database
createDb()

#Bold font
font='Helvetica 16 bold'

#Domain field
tk.Label(text="Site/User:", font=font).grid(row=0, column=1)
domainEntry = tk.Entry(root)
domainEntry.grid(row = 0, column = 2)

#Password field
tk.Label(text="Password:", font=font).grid(row=1, column=1)    
pwdEntry = tk.Entry(root)
pwdEntry.grid(row = 1, column = 2)

#Save btn
saveBtn = tk.Button(root, text="Save", width=17, command=save)
saveBtn.grid(row = 2, column = 2)

#Random btn
randPwd = tk.Button(root, text="Random\n Password", height=3, width=17, command=rand)
randPwd.grid(row = 2, column = 1, rowspan=2)

#Show btn
showBtn = tk.Button(root, text="Show all", width=17, command=show)
showBtn.grid(row = 3, column = 2)

tk.Label(text="Info", font=font, width=12).grid(row=0, column=3)
tk.Label(text="Click on password to copy", justify='left', anchor='w').grid(row=1, column=3)
tk.Label(text="Made by WIXO.").grid(row=2, column=3)
tk.Label(text=f"Version: {version}").grid(row=3, column=3)


#Empty row
tk.Label(text=" ").grid(row=4, column=0, columnspan=3)

root.mainloop()