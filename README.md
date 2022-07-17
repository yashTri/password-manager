A simple and secure password manager.

To install dependencies, use: `pip install -r requirements.txt`

### Usage

In order to run the application, run the follwing command: 

```
python3 PasswordManager.py
```

If you are using this application for the first time, enter the master password (which will be used to encrypt all the other information).
If not, enter your master password
Then, press Enter or click on 'Enter'.


To add a new login, click on add and fill the details, then click 'Save' (or hit Enter to save)

To update login info, click on the row you want to edit and click 'Update' - it will be unlocked for you to edit.
After editing it, click 'Save' (or hit Enter to save).

Note - info will not be saved if any entry is empty.

To delete a login, click on the row you want to delete and then click on 'Delete'. A confirmation box will pop up - select Yes to delete.

Click on 'Generate Password' while editing to generate a random password while editing.

Note - If you delete master.txt or psswd.db, all your information will be lost.
