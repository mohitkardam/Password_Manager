import tkinter as tk
from tkinter import simpledialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Salt file for key derivation
SALT_FILE = "salt.bin"

# Generate and save the salt
def write_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as salt_file:
            salt_file.write(salt)

def load_salt():
    try:
        return open(SALT_FILE, "rb").read()
    except FileNotFoundError:
        messagebox.showerror("Error", "Salt file not found!")
        return None

def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Encrypt a message
# (key is now derived from master password)
def encrypt_message(message, key):
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    return encrypted

# Decrypt a message
def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_message)
    return decrypted.decode()

# Setup GUI
root = tk.Tk()
root.geometry("350x350")
root.title("Password Manager")

# Prompt for master password at startup and derive key
write_salt()
salt = load_salt()
master_password = None
key = None

def prompt_master_password():
    global master_password, key
    while True:
        master_password = simpledialog.askstring("Master Password", "Enter your master password:", show='*', parent=root)
        if not master_password:
            if messagebox.askyesno("Exit", "No master password entered. Exit?"):
                root.destroy()
                return False
            continue
        try:
            key_candidate = derive_key_from_password(master_password, salt)
            # Try to decrypt one password to check validity, if any exist
            if os.path.exists("passwords.txt"):
                with open("passwords.txt", "rb") as f:
                    for line in f:
                        line = line.decode().strip()
                        if not line or ':' not in line:
                            continue
                        _, encrypted = line.split(':', 1)
                        encrypted = encrypted.strip()
                        try:
                            decrypt_message(encrypted.encode(), key_candidate)
                        except Exception:
                            raise ValueError("Incorrect master password.")
                        break  # Only check the first valid password
            key = key_candidate
            return True
        except Exception:
            messagebox.showerror("Error", "Incorrect master password. Please try again.")

if not prompt_master_password():
    exit()

def save_password():
    title = title_entry.get()
    password = password_entry.get()
    if not title or not password:
        result_label.config(text="All fields are required!", fg="red")
        return
    try:
        encrypted = encrypt_message(password, key)
        with open("passwords.txt", "ab") as f:
            f.write(f"{title}: {encrypted.decode()}\n".encode())
        result_label.config(text="Password saved!", fg="green")
    except Exception as e:
        result_label.config(text="Error saving password!", fg="red")
        print(e)

def view_passwords_gui():
    if not os.path.exists("passwords.txt"):
        messagebox.showinfo("No Passwords", "No passwords have been saved yet.")
        return
    try:
        with open("passwords.txt", "rb") as f:
            lines = f.readlines()
        decrypted_passwords = []
        for line in lines:
            try:
                line = line.decode().strip()
                if not line:
                    continue
                if ':' not in line:
                    continue
                title, encrypted = line.split(':', 1)
                encrypted = encrypted.strip()
                decrypted = decrypt_message(encrypted.encode(), key)
                decrypted_passwords.append(f"{title}: {decrypted}")
            except Exception as e:
                decrypted_passwords.append(f"Error decrypting a password: {e}")
        if decrypted_passwords:
            messagebox.showinfo("Saved Passwords", "\n".join(decrypted_passwords))
        else:
            messagebox.showinfo("Saved Passwords", "No passwords found.")
    except Exception as e:
        messagebox.showerror("Error", f"Could not read passwords: {e}")

def manage_passwords_gui():
    if not os.path.exists("passwords.txt"):
        messagebox.showinfo("No Passwords", "No passwords have been saved yet.")
        return
    try:
        with open("passwords.txt", "rb") as f:
            lines = f.readlines()
        entries = []
        for line in lines:
            try:
                line = line.decode().strip()
                if not line or ':' not in line:
                    continue
                title, encrypted = line.split(':', 1)
                entries.append((title.strip(), encrypted.strip()))
            except Exception:
                continue
        if not entries:
            messagebox.showinfo("No Passwords", "No valid passwords found.")
            return
        # Create management window
        mgmt_win = tk.Toplevel(root)
        mgmt_win.title("Manage Passwords")
        mgmt_win.geometry("450x550")
        tk.Label(mgmt_win, text="Select an entry:").pack()
        listbox = tk.Listbox(mgmt_win, width=40)
        for title, _ in entries:
            listbox.insert(tk.END, title)
        listbox.pack(pady=5)
        def edit_selected():
            sel = listbox.curselection()
            if not sel:
                messagebox.showwarning("Select Entry", "Please select an entry to edit.")
                return
            idx = sel[0]
            title, encrypted = entries[idx]
            try:
                old_password = decrypt_message(encrypted.encode(), key)
            except Exception as e:
                messagebox.showerror("Error", f"Could not decrypt: {e}")
                return
            new_password = simpledialog.askstring("Edit Password", f"Enter new password for '{title}':", show='*', initialvalue=old_password)
            if not new_password:
                return
            try:
                new_encrypted = encrypt_message(new_password, key).decode()
                entries[idx] = (title, new_encrypted)
                # Write all entries back
                with open("passwords.txt", "wb") as f:
                    for t, e in entries:
                        f.write(f"{t}: {e}\n".encode())
                messagebox.showinfo("Success", "Password updated.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not update: {e}")
        def delete_selected():
            sel = listbox.curselection()
            if not sel:
                messagebox.showwarning("Select Entry", "Please select an entry to delete.")
                return
            idx = sel[0]
            title, _ = entries[idx]
            if not messagebox.askyesno("Confirm Delete", f"Delete password for '{title}'?"):
                return
            del entries[idx]
            # Write all entries back
            with open("passwords.txt", "wb") as f:
                for t, e in entries:
                    f.write(f"{t}: {e}\n".encode())
            listbox.delete(idx)
            messagebox.showinfo("Deleted", f"Password for '{title}' deleted.")
        btn_frame = tk.Frame(mgmt_win)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Edit", command=edit_selected).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Delete", command=delete_selected).pack(side=tk.LEFT, padx=5)
    except Exception as e:
        messagebox.showerror("Error", f"Could not read passwords: {e}")

tk.Label(root, text="Title").pack(pady=(20, 0))
title_entry = tk.Entry(root)
title_entry.pack()
tk.Label(root, text="Password").pack()
password_entry = tk.Entry(root, show='*')
password_entry.pack()

save_button = tk.Button(root, text="Save Password", command=save_password)
save_button.pack(pady=(10, 0))

view_button = tk.Button(root, text="View Passwords", command=view_passwords_gui)
view_button.pack(pady=(5, 0))

manage_button = tk.Button(root, text="Manage Passwords", command=manage_passwords_gui)
manage_button.pack(pady=(5, 0))

result_label = tk.Label(root, text="", font=('Helvetica', 10))
result_label.pack()

root.mainloop()
