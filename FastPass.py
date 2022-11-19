import tkinter as tk
import random
import sqlite3
from datetime import date

version = "1.0.0 (Alpha)"
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

        sqlite_insert_query = f"INSERT INTO users(website, password, creation_date) VALUES ('{inpDom}', '{inpPwd}', '{currentDate}');"
        cursor.execute(sqlite_insert_query)
        connection.commit()
        print(f"INFO: {inpDom}, {inpPwd}, ({currentDate}) - ADDED TO DATABASE")
        pwdEntry.delete(0, "end")
        domainEntry.delete(0, "end")
        show()

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

        data1 = tk.Label(root, text="Website")
        data1.grid(row=5, column=1)
        data2 = tk.Label(root, text="Password")
        data2.grid(row=5, column=3)
        data3 = tk.Label(root, text="Last update")
        data3.grid(row=5, column=2)

        dataRow = 6
        for i in data:
            tk.Label(root, text=f"{i[0]}").grid(row=dataRow, column=1)
            tk.Label(root, text=f"{i[1]}").grid(row=dataRow, column=3)
            tk.Label(root, text=f"{i[2]}").grid(row=dataRow, column=2)
            tk.Button(root, text="Copy to clipboard").grid(row=dataRow, column=6)
            dataRow += 1
                              

    except sqlite3.Error as error:
        print("Error while connecting to sqlite", error)

    finally:
        if connection:
            connection.close()
            print("The SQLite connection is closed")

#Create database
createDb()

#Domain field
tk.Label(text="Website:").grid(row=0, column=1)
domainEntry = tk.Entry(root)
domainEntry.grid(row = 0, column = 2)

#Password field
tk.Label(text="Password:").grid(row=1, column=1)    
pwdEntry = tk.Entry(root)
pwdEntry.grid(row = 1, column = 2)

#Save btn
saveBtn = tk.Button(root, text="Save", command=save)
saveBtn.grid(row = 2, column = 2)

#Random btn
randPwd = tk.Button(root, text="Random", command=rand)
randPwd.grid(row = 0, column = 3, rowspan=2)

#Show
showtest = tk.Button(root, text="Show", command=show)
showtest.grid(row = 0, column = 5, rowspan=2, columnspan=2)

#Empty row - Does nothing
tk.Label(text="").grid(row=3, column=0)



root.mainloop()