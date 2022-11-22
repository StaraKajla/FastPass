# FastPass<br>
Local password manager

**How to run:**<br>
pip install -r requrements.txt<br>
Download sourcecode and run it. On first run the app will create its own database.

**Current functionality:**<br>
Program creates local database and saves passwords encrypted with AES 256 and cipherkey. <br>
To retrieve passwords from database you must provide the same key that was used when a password was saved.<br>
If cipher key is incorrect, no password will be returned.<br>
For additional security you can select different cypher keys for each password.<br>
If cipher key is correct you can copy password from GUI on click from the button.

**NOTE**<br>
It is advised to keep a duplicate copy of the password database incase you or an adversary deletes it.<br>
A good idea is to follow [3 2 1 back-up rule](https://www.google.com/search?q=3+2+1+backup+rule)

**TODO:** <br>
Add multiple user support.
Add hide button.