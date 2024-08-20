#!/usr/bin/env python3

import os
from datetime import datetime
import pytz
from colorama import Fore, Style, init
from cryptography.fernet import Fernet
import base64
import hashlib

# Initialize colorama
init(autoreset=True)

# Set TERM environment variable if it's not set
if 'TERM' not in os.environ:
    os.environ['TERM'] = 'xterm'

# Function to generate a key from a password
def generate_key(password: str) -> bytes:
    """Generate a key from the given password."""
    hasher = hashlib.sha256()
    hasher.update(password.encode())
    return base64.urlsafe_b64encode(hasher.digest()[:32])

def encrypt_file(file_path: str, password: str):
    """Encrypt the file with the given password."""
    key = generate_key(password)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        original_data = file.read()

    encrypted_data = fernet.encrypt(original_data)

    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(file_path: str, password: str) -> bytes | None:
    """Decrypt the file with the given password and return the decrypted data."""
    key = generate_key(password)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data
    except Exception as e:
        print(Fore.RED + f"Decryption error: {e}")
        return None

def get_downloads_folder() -> str:
    """Get the path to the user's Downloads folder."""
    if os.name == 'nt':  # For Windows
        return os.path.join(os.getenv('USERPROFILE'), 'Downloads')
    else:  # For macOS and Linux
        return os.path.join(os.path.expanduser('~'), 'Downloads')

def display_banner():
    """Display the banner with ASCII art and custom message."""
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear the terminal screen

    print(Fore.GREEN + """
░▒▓█▓▒░         ░▒▓██████▓▒░   ░▒▓██████▓▒░  ░▒▓███████▓▒░   ░▒▓██████▓▒░   ░▒▓██████▓▒░  ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒▒▓███▓▒░ ░▒▓███████▓▒░  ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓███████▓▒░  
░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓████████▓▒░  ░▒▓██████▓▒░   ░▒▓██████▓▒░  ░▒▓███████▓▒░   ░▒▓██████▓▒░   ░▒▓██████▓▒░  ░▒▓█▓▒░░▒▓█▓▒░   
                                            Program by sievlong Pov                                                                                                                                                                                                                                                                               
    """ + Style.RESET_ALL)

def display_menuoption():
    print("1. Start logging")
    print("2. View an encrypted file")
    print("3. Exit")

def get_log_file() -> str:
    """Get the name of the log file and save it to the Downloads folder."""
    downloads_folder = get_downloads_folder()
    while True:
        print(Fore.GREEN + "|----Log Book System----|")
        print("1. Create a new logbook")
        print("2. Continue with an existing logbook")
        print("3. Exit")

        choice = input(Fore.GREEN + "Select an option (1/2/3): ").strip()

        if choice == '1':
            logbook_name = input("Enter the name for the new logbook: ").strip()
            if not logbook_name.endswith('.txt'):
                logbook_name += '.txt'
            return os.path.join(downloads_folder, logbook_name)

        elif choice == '2':
            print(Fore.RED + """
                        WARNING: Make sure the file is not encrypted!
                        """ + Style.RESET_ALL)
            logbook_name = input("Enter the name of the existing logbook (must be a .txt file): ").strip()
            if not logbook_name.endswith('.txt'):
                logbook_name += '.txt'
            logbook_path = os.path.join(downloads_folder, logbook_name)
            if os.path.exists(logbook_path):
                return logbook_path
            else:
                print(Fore.RED + "The specified logbook does not exist or is empty. Please create a new logbook.")

        elif choice == '3':
            exit(Fore.RED + "Exiting the program.")

        else:
            print(Fore.RED + "Invalid choice. Please type '1'/'2' or '3'.")

def log_entry(log_file: str, password=None):
    """Append new notes to the log file with a timestamp and waiting time message."""
    try:
        # Prompt user for logbook details
        task_details = input("Task Details: ").strip()
        user_name = input("Enter your Name: ").strip()
        user_id = input("Enter your ID: ").strip()
        user_location = input("Enter your Location: ").strip()
        copyright = "Powered by logbook. Created By sievlong Pov."

        with open(log_file, 'a') as file:
            # Create a boxed About section and user info
            user_info = (
                f"Name: {user_name}\n"
                f"ID: {user_id}\n"
                f"Location: {user_location}\n"
                f"Task Details: {task_details}\n"
                f""
                f"Copyright: {copyright}\n"
            )
            file.write(create_boxed_text(user_info) + "\n")

            # Write header info to the file
            file.write("Date | Time (UTC) | Time since last entry | Log\n")
            file.write("=" * 80 + "\n")

            print(Fore.GREEN + "Logging started. Type your notes. Type 'end' to stop.")
            last_entry_time = datetime.now(pytz.utc)  # Initial time for the first note

            while True:
                note = input("Enter your Log (or type 'end' to stop): ")
                if note.lower() == 'end':
                    print(Fore.GREEN + "Logging ended.")
                    break

                current_time = datetime.now(pytz.utc)  # Get current time in UTC

                # Calculate waiting time since the last entry
                waiting_time = current_time - last_entry_time1
                time_since_last_entry = waiting_time.total_seconds()

                # Write log entry to the file
                timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
                date = current_time.strftime("%Y-%m-%d")

                file.write(
                    f"{timestamp} | Date: {date} | Time since last entry: "
                    f"{time_since_last_entry:.2f} seconds | Log: {note}\n")

                # Update the last entry time
                last_entry_time = current_time

        # Encrypt the file if a password is provided
        if password:
            encrypt_file(log_file, password)
            print(Fore.GREEN + "The logbook has been encrypted.")

    except Exception as e:
        print(Fore.RED + f"An error occurred while logging: {e}")

def create_boxed_text(text: str) -> str:
    """Create a boxed text block with a given message."""
    lines = text.split('\n')
    max_length = max(len(line) for line in lines)
    border = '─' * (max_length + 4)
    boxed_lines = [f"│ {line.ljust(max_length)} │" for line in lines]
    return f"┌{border}┐\n" + "\n".join(boxed_lines) + f"\n└{border}┘"

def view_encrypted_file():
    """View the contents of an encrypted file by decrypting it temporarily."""
    file_path = input(Fore.GREEN + "Enter the path to the encrypted file: ").strip()

    # Check if the file exists
    if not os.path.isfile(file_path):
        print(Fore.RED + "The specified file does not exist. Please check the file path.")
        return  # Exit the function to return to the menu

    retries = 3  # Number of allowed password retries
    downloads_folder = get_downloads_folder()  # Get path to Downloads folder

    while retries > 0:
        password = input("Enter the password for decryption: ").strip()

        try:
            # Decrypt the file and write the decrypted content to a temporary file
            decrypted_data = decrypt_file(file_path, password)

            if decrypted_data is None:
                print(Fore.RED + "Decryption failed. Please check the password.")
                retries -= 1
                if retries > 0:
                    print(Fore.RED + f"You have {retries} attempts left.")
                else:
                    print(Fore.RED + "You have exhausted all attempts. Returning to the menu.")
                continue  # Retry password input
            else:
                # Save decrypted content to Downloads folder
                temp_file_path = os.path.join(downloads_folder, 'temp_decrypted_file.txt')
                with open(temp_file_path, 'wb') as file:
                    file.write(decrypted_data)

                print(Fore.GREEN + "Decrypted Content:")
                with open(temp_file_path, 'r') as file:
                    print(file.read())

                # Inform the user where the file is saved
                print(Fore.GREEN + f"The decrypted file has been saved as '{temp_file_path}'.")
                return  # Exit the function after successful decryption

        except Exception as e:
            retries -= 1
            if retries > 0:
                print(Fore.RED + f"An error occurred while viewing the file: {e}")
                print(Fore.RED + f"You have {retries} attempts left.")
            else:
                print(Fore.RED + "You have exhausted all attempts. Returning to the menu.")
                break  # Exit the loop after all attempts have been used

def main():
    display_banner()

    while True:
        display_menuoption()
        user_input = input(Fore.GREEN + "Select an option (1/2/3): ").strip()

        if user_input == '1':
            log_file = get_log_file()
            print(Fore.RED + """
            WARNING: You cannot log or write to an encrypted file directly.
            You must decrypt the file first to make any changes. 
            Failing to do so may result in overwriting the file. 
            Please decrypt the file, make your changes, and then re-encrypt it to ensure data security.
            """ + Style.RESET_ALL)
            encrypt_option = (input(Fore.GREEN + "Do you want to password-protect this logbook? (yes/no): ").strip()
                              .lower())
            password = None
            if encrypt_option == 'yes':
                password = input("Enter a password for encryption: ").strip()
            log_entry(log_file, password)
            print(Fore.GREEN + f"Logs have been saved to {log_file}")
        elif user_input == '2':
            view_encrypted_file()
        elif user_input == '3':
            print(Fore.RED + "Exiting the program.")
            break
        else:
            print(Fore.RED + "Invalid input. Please type '1' to begin logging, "
                             "'2' to view an encrypted file, or '3' to quit.")

if __name__ == "__main__":
    main()
