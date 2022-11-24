# FastPass<br>
Local password manager

**How to run:**<br>
pip install -r requrements.txt<br>
Download sourcecode and run it. On first run the app will create its own database.

**Current functionality:**<br>
Multiple user support<br>
AES 256 encryption with 15.000 PBKDF2 iterations using provided Secret Key(Optional)<br>
Delete stored passwords<br>
Local database<br>

**INFO**<br>
To retrieve passwords from database you must **provide the same key that was used when a password was saved**.<br>
If secret key is incorrect, no password will be returned.<br>
For additional security you can select different Secret Keys for each password.<br>
If secret key is correct you can copy password from GUI on click.

**NOTE**<br>
If you use a Secret Key make sure you **do not lose it** because database doesn't store it!
It is advised to keep a duplicate copy of the password database incase of accidental deletion.<br>
A good idea is to follow [3 2 1 backup rule](https://www.google.com/search?q=3+2+1+backup+rule)

**TODO:** <br>
Sort stored passwords by alphabetically sorting websites.<br>
Add scrollbar
