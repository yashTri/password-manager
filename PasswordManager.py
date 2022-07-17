import hashlib
import os
import sqlite3
from tkinter import *
from tkinter import ttk
import random
import string
from tkinter import messagebox
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# function that inserts a new randomly generated password in the password entry of the row being edited 
def genPass():
    global beingEdited
    variabletable[beingEdited][2].set(''.join(random.choices(string.ascii_letters + string.digits + '@!*.#', k = 20)))


# function to encrypt a message with a password using AES (128-bit)
def encrypt(message, password):
    # generate random salt
    salt = get_random_bytes(AES.block_size)
    # generate key from password using scrypt key derivation function
    key = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=32)
    # create new AES object
    cipherNew = AES.new(key, AES.MODE_GCM)
    # encrypt and store the message in cipherText and tag
    cipherText, tag = cipherNew.encrypt_and_digest(bytes(message, 'utf-8'))
    # store cipherText, salt, nonce and tag in after encoding in base64, separated by '-', after encoding in utf-8
    encryptedMessage = b64encode(cipherText).decode('utf-8') + '-' + \
                       b64encode(salt).decode('utf-8') + '-' +\
                       b64encode(cipherNew.nonce).decode('utf-8') + '-' +\
                       b64encode(tag).decode('utf-8')
    # return the message
    return encryptedMessage

#function to decrypt an encrypted string using a password
def decrypt(encString, password):
    # split the message into a list (separator is '-')
    encList = encString.split("-")
    # store the values of ciphertext, salt, nonce and tag after decoding from base64
    cipherText = b64decode(encList[0])
    salt = b64decode(encList[1])
    nonce = b64decode(encList[2])
    tag = b64decode(encList[3])
    # generate key using the salt and password
    key = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=32)
    # create new AES object
    cipherNew = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # ValueError can be raised if tag does not match or because of any other reason
    try:
        # decrypt text 
        decryptedText = cipherNew.decrypt_and_verify(cipherText, tag)
    except:
        # if exception occurs, return false
        return False
    # return decrypted text in utf-8
    return decryptedText.decode('utf-8')

# function to delete the row that was last selected
def delete():
    global lastActive
    global entrytable
    # only delete if some row was selected
    if lastActive != -1:
        # ask the user for confirmation
        if messagebox.askyesno(title="Confirm deletion", message="Do you want to delete this login?"):
            site = encryptedVals[lastActive][0]
            usr = encryptedVals[lastActive][1]
            pss = encryptedVals[lastActive][2]
            for i in entrytable[lastActive]:
               i.destroy()
            c = conn.cursor()
            c.execute('DELETE FROM passwords WHERE website = ? AND username = ? AND password = ?', (site, usr, pss))
            conn.commit()
            lastActive = -1

# function to set num as the last selected row
def lastSel(num):
    global lastActive
    lastActive = num

# function to save the contents of the row being edited last
def savecont(*args):

    # unbind the Enter key from the savecont function
    root.unbind("<Return>")

    # get the new values of website, username and password from the StringVar objects
    site = variabletable[beingEdited][0].get()
    usr = variabletable[beingEdited][1].get()
    pss = variabletable[beingEdited][2].get()

    # only save if none of the values are not empty
    if site != '' and usr != '' and pss != '':
        # disable the Save and Generate Password buttons after saving
        addButton['state'] = NORMAL
        saveButton['state'] = DISABLED
        updateButton['state'] = NORMAL
        deleteButton['state'] = NORMAL
        genPassButton['state'] = DISABLED

        # store the new values in encryptedVals list after encrypting them with the master password 
        encryptedVals[beingEdited][0] = encrypt(site, master_password)
        encryptedVals[beingEdited][1] = encrypt(usr, master_password)
        encryptedVals[beingEdited][2] = encrypt(pss, master_password)

        # create a cursor to the database connection
        c = conn.cursor()
        # insert the values into the database
        c.execute('INSERT INTO passwords VALUES(?, ?, ?)', (encryptedVals[beingEdited][0],
                                                            encryptedVals[beingEdited][1],
                                                            encryptedVals[beingEdited][2]))
        # commit changes to the database
        conn.commit()
        # change the state of the entries being edited to readonly after saving
        for i in entrytable[beingEdited]:
            i['state'] = 'readonly'
        global lastActive
        # set lastactive to -1 as no row is selected after saving
        lastActive = -1

# function to unlock the row of entries that were last selected to edit them        
def updatevals(*args):
    global beingEdited, lastActive
    beingEdited = lastActive
    # bind the enter key to the savecont function (the save function)
    root.bind("<Return>", savecont)
    if beingEdited != -1:
        entrytable[beingEdited][0].focus()
        for i in entrytable[beingEdited]:
            i['state'] = 'normal'
        # disable all the buttons except Save and Generate Password
        addButton['state'] = DISABLED
        saveButton['state'] = NORMAL
        updateButton['state'] = DISABLED
        deleteButton['state'] = DISABLED
        genPassButton['state'] = NORMAL

        # get the original values for the row being edited
        site = encryptedVals[beingEdited][0]
        usr = encryptedVals[beingEdited][1]
        pss = encryptedVals[beingEdited][2]
        # delete the original values from the database
        c = conn.cursor()
        c.execute('DELETE FROM passwords WHERE website = ? AND username = ? AND password = ?;', (site, usr, pss))
        conn.commit()

# function to add new information    
def addnew(state, site, usr, pss):
    global mainframe
    global entrytable
    global idnum
    # bind the Enter key to the savecont function
    root.bind("<Return>", savecont)
    # if the user is adding a new entry, and it is not an old entry from the database
    if state == 'new':
        # disable all the buttons except the Save and Generate Password button
        addButton['state'] = DISABLED
        saveButton['state'] = NORMAL
        updateButton['state'] = DISABLED
        deleteButton['state'] = DISABLED
        genPassButton['state'] = NORMAL
        global beingEdited
        # set the row being edited to the new row
        beingEdited = idnum
    # create a local variable to use in the lambda function for last selected row 
    i = idnum
    # append a list of 3 new StringVars() that will be the variables for the entries
    variabletable.append([StringVar(), StringVar(), StringVar()])
    # append a list of 3 entries for a new login
    entrytable.append([ttk.Entry(mainframe, textvariable=variabletable[idnum][0]),
                       ttk.Entry(mainframe, textvariable=variabletable[idnum][1]),
                       ttk.Entry(mainframe, textvariable=variabletable[idnum][2])])
    if state == 'old':
        # append the encrypted values from the database into the encryptedVals list
        encryptedVals.append([site, usr, pss])
        # set the StringVar objects for the entries with the values from the database decrypted using the master password
        variabletable[i][0].set(decrypt(site, master_password))
        variabletable[i][1].set(decrypt(usr, master_password))
        variabletable[i][2].set(decrypt(pss, master_password))
        # set the the state of these entries to readonly
        for j in entrytable[i]:
            j["state"] = 'readonly'
    # place the entries in the grid
    for j in range(3):
        entrytable[i][j].grid(column=j + 1, row=i + 3, sticky=(W, E))    
    # bind the focus-out event for this entry with lastSel(i) to set lastActive to i whenever this row was the last selected
    for j in entrytable[i]:
        j.bind('<FocusOut>', lambda e:lastSel(i))

    if state == 'new':
        entrytable[i][0].focus()
        # if this is a new entry, append empty values to encryptedVals table (will be changed when saved)
        encryptedVals.append(['', '', ''])
    # increase idnum by 1
    idnum += 1
    
# function to check if the user has entered the right master password
def check(*args):
    # store the value entered by the user in val
    val = passVal.get()
    global master_password
    # do only if the password field was not empty
    if val != '':
        global conn

        if isFirst:
            # if this is the first time, create the database with a table named passwords and a file for storing the encrypted master password
            # which is entered by the user
            conn = sqlite3.connect("psswd.db")
            c = conn.cursor()
            c.execute('CREATE TABLE passwords (website TEXT, username TEXT, password TEXT);')
            conn.commit()
            conn.close()
            file = open("master.txt", "w");
            # encrypt the user entered password and store it int master.txt
            file.write(encrypt(val, val))
            file.close()
            master_password = open('master.txt', 'r').read()
            
        # check if the master password, when decrypted with the password entered by the user, is equal to it (always true if this is the first time)
        if decrypt(master_password, val) == val:
            # unbind the enter key from check
            root.unbind("<Return>")
            # store the master password in master_password
            master_password = val
            global mainframe
            global addButton
            global saveButton
            global updateButton
            global deleteButton
            global genPassButton
            # create a new frame within which all widgets will be placed
            mainframe = ttk.Frame(root, padding="3 3 12 12")
            # place it within the grid
            mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
            # configure root so that mainframe also resizes when root is resized
            root.columnconfigure(0, weight=1)
            root.rowconfigure(0, weight=1)
            # connect to database
            conn = sqlite3.connect("psswd.db")
            # set row_factory to Row, so that data can be accessed in a dictionary-like manner
            conn.row_factory = sqlite3.Row
            # create cursor to database
            c = conn.cursor()
            # select all passwords from the passwords table
            c.execute('select * from passwords;')
            # store all the data in data
            data = c.fetchall()
            # configure the first three columns (username, website and password) to be resizable
            mainframe.columnconfigure(1, weight=1)
            mainframe.columnconfigure(2, weight=1)
            mainframe.columnconfigure(3, weight=1)
            # create labels for website, username and password
            ttk.Label(mainframe, text="Website").grid(column=1, row=2)
            ttk.Label(mainframe, text="Username").grid(column=2, row=2)
            ttk.Label(mainframe, text="Password").grid(column=3, row=2)
            # add new entries for all the old values that were stored in the database
            for row in data:
                addnew('old', row['website'], row['username'], row['password'])
            # create buttons and place them in the grid
            addButton = ttk.Button(mainframe, text="Add", command=lambda: addnew("new",'','',''))
            saveButton = ttk.Button(mainframe, text='Save', command=savecont)
            updateButton = ttk.Button(mainframe, text='Update', command=updatevals)
            deleteButton = ttk.Button(mainframe, text='Delete', command=delete, width=7)
            genPassButton = ttk.Button(mainframe, text='Generate Password', command=genPass, width=20)
            addButton.grid(column=1, row=1, sticky=(W, E))
            saveButton.grid(column=2, row=1, sticky=(W, E))
            updateButton.grid(column=3, row=1, sticky=(W, E))
            deleteButton.grid(column=4, row=1, sticky=(W, E))
            genPassButton.grid(column=5, row=1, sticky=(W, E))
            # initially, disable the Save and Generate Password buttons
            addButton['state'] = NORMAL
            saveButton['state'] = DISABLED
            updateButton['state'] = NORMAL
            deleteButton['state'] = NORMAL
            genPassButton['state'] = DISABLED
        else:
            # set the message if the value is wrong (will never happen for first time)
            passMessage.set("Incorrect password :(")

# variable to store master password
master_password = ''
# variable to indicate whether this is the first time the application is being used or not
isFirst=False
# check if this is the first time the user is using the application
if os.path.exists("psswd.db") == False or os.path.exists("master.txt") == False:
    # set isFirst to true if this is the first time
    isFirst = True
else:
    # store the encrypted password from master.txt in master_password
    master_password = open('master.txt', 'r').read()
# create the main application window (root)
root = Tk()
# set title of the window to password manager
root.title('Password manager')


# list of lists of StringVar objects for storing the entries
variabletable = []
# list of lists of strings which store the info in encrypted form
encryptedVals = []
# list of lists of entry widgets which display the information in the form of a table where each row
# corresponds to (website, username, password)
entrytable = []

# variable that stores the last row which was selected (in keyboard focus)
lastActive = -1
# unique id for each login
idnum = 0
# variable that stores the row number of the row that is currently being edited
beingEdited = -1


# buttons to add, save, update and delete info, and also to generate a random password when editing a row
addButton = 0
saveButton = 0
updateButton = 0
deleteButton = 0
genPassButton = 0

# creating a mainframe inside which all the other widgets will be placed
mainframe = ttk.Frame(root, padding="3 3 12 12")
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
# configure the frame to resize with root
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# this will store the connection with the database
conn = 0

#StringVar for the password enterd by the user
passVal = StringVar()
# entry for storing password entered by the user
passVal_entry = ttk.Entry(mainframe, width=30, textvariable=passVal)
passVal_entry.grid(column=1, row=1, sticky=(N, S, E, W))

# StringVar for the message displayed to the user
passMessage = StringVar()
# set the message according to the usage (first time or not)
if isFirst:
    passMessage.set("Set password")
else:
    passMessage.set("Enter the password")
# place a label for this message and place it in the grid
ttk.Label(mainframe, textvariable=passMessage).grid(column=1, row=3, sticky = (N))

# create a button to enter and check password
b = ttk.Button(mainframe, text="Enter", command=check).grid(column=1, row=2, sticky=(N, S, E, W))
# configure the first column to be resizable horizontally
mainframe.columnconfigure(1, weight=1)
# focus the password entry
passVal_entry.focus()
# bind the Enter key to check
root.bind("<Return>", check)
root.mainloop()
