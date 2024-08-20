# logbook
## Overview

The Logbook Encryption System is a Python script designed to manage logbooks with encryption support. Users can create, append to, and view logbooks with the option to encrypt the files using a password. This script supports both logging new entries and decrypting existing encrypted logbooks.

## Features

- **Logbook Creation & Management**: Create new logbooks or continue with existing ones.
- **Encryption**: Encrypt logbooks with a password for added security.
- **Decryption**: View the contents of encrypted logbooks by decrypting them temporarily.
- **Decryption and File Handling**: After decrypting a file, a permanent copy of the decrypted content will be created. This ensures that the decrypted data is kept separate from the original encrypted file. Always handle decrypted files with care and re-encrypt them if necessary.
- **Logging**: Automatic Add timestamped entries to the logbook with a waiting time calculation since the last entry.

## Requirements

- Python 3.x
- `cryptography` library
- `colorama` library
- `pytz` library

You can install the required libraries using pip:

```bash
pip install cryptography colorama pytz
```

## Usage
**1. Install For Mac/Linux**

```bash
sudo git clone https://github.com/sievlong/logbook.git
```
**2. Install for Window**

```bash
git clone https://github.com/sievlong/logbook.git
```
**3. Run the Script**

To start the script, run: 
```bash
python logbook.py
```


## Menu Options

1. **Start Logging**: 
   - Create a new logbook or continue with an existing one.
   - You will be prompted to enter log details and optionally password-protect the logbook.

2. **View an Encrypted File**: 
   - Enter the path to an encrypted logbook file to view its contents.
   - You will need to provide the correct password for decryption.

3. **Exit**: 
   - Exit the program.

## Creating a Logbook

- You will be prompted to create a new logbook or continue with an existing one.
- If you choose to create a new logbook, specify a name (the default extension is `.txt`).
- Optionally, you can encrypt the logbook by providing a password.

## Appending to Logbook

- Provide details for each log entry, such as task details, name, ID, and location.
- Type `'end'` to finish logging.

## Viewing Encrypted Files

- Provide the path to the encrypted logbook file.
- Enter the correct password to decrypt and view the file content.

## Author

Created by sievlong Pov.
Pleace give credit!
Contact Info: 
[Facebook](https://www.facebook.com/pov.sievlong/)
[Instagram](https://www.instagram.com/sievlong.p/)
[LinkedIN](https://www.linkedin.com/in/sievlong-pov-aa1023248/)
[Gmail](pov.sievlong@gmail.com)

## Acknowledgements

- This script uses the cryptography library for encryption and decryption.
- colorama is used for colored terminal text output.
- pytz provides timezone support for timestamps.
