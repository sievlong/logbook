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

## Usage
1. Run the Script
