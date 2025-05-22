from tkinter import *
from tkinter import messagebox
import base64
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

# Function to encrypt the text
def encrypt_text():
    encryption_key = encryption_key_entry.get()
    if encryption_key:
        message = text_entry.get("1.0", END).strip()
        cipher_choice = cipher_var.get()
        if message:
            try:
                if cipher_choice == "Base64":
                    encrypted = base64.b64encode(message.encode()).decode()
                elif cipher_choice == "DES":
                    key = encryption_key[:8].ljust(8).encode()  # Ensure key is 8 bytes
                    des = DES.new(key, DES.MODE_ECB)
                    encrypted = des.encrypt(pad(message.encode(), DES.block_size))
                    encrypted = base64.b64encode(encrypted).decode()
                elif cipher_choice == "AES":
                    key = encryption_key[:16].ljust(16).encode()  # Ensure key is 16 bytes
                    aes = AES.new(key, AES.MODE_ECB)
                    encrypted = aes.encrypt(pad(message.encode(), AES.block_size))
                    encrypted = base64.b64encode(encrypted).decode()
                else:
                    messagebox.showerror("Error", "Invalid Cipher!")
                    return

                output_text.config(state="normal")
                output_text.delete("1.0", END)
                output_text.insert("1.0", encrypted)
                output_text.config(state="disabled")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed! {str(e)}")
        else:
            messagebox.showerror("Error", "No text provided!")
    else:
        messagebox.showerror("Error", "Encryption Key is required!")

# Function to decrypt the text
def decrypt_text():
    encryption_key = encryption_key_entry.get()
    if encryption_key:
        message = text_entry.get("1.0", END).strip()
        cipher_choice = cipher_var.get()
        if message:
            try:
                if cipher_choice == "Base64":
                    padded_message = message + "=" * ((4 - len(message) % 4) % 4)
                    decrypted = base64.b64decode(padded_message.encode()).decode()
                elif cipher_choice == "DES":
                    key = encryption_key[:8].ljust(8).encode()  # Ensure key is 8 bytes
                    des = DES.new(key, DES.MODE_ECB)
                    decrypted = unpad(des.decrypt(base64.b64decode(message)), DES.block_size).decode()
                elif cipher_choice == "AES":
                    key = encryption_key[:16].ljust(16).encode()  # Ensure key is 16 bytes
                    aes = AES.new(key, AES.MODE_ECB)
                    decrypted = unpad(aes.decrypt(base64.b64decode(message)), AES.block_size).decode()
                else:
                    messagebox.showerror("Error", "Invalid Cipher!")
                    return

                output_text.config(state="normal")
                output_text.delete("1.0", END)
                output_text.insert("1.0", decrypted)
                output_text.config(state="disabled")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed! {str(e)}")
        else:
            messagebox.showerror("Error", "No text provided!")
    else:
        messagebox.showerror("Error", "Encryption Key is required!")

# Function to copy output to clipboard
def copy_to_clipboard():
    output_text_content = output_text.get("1.0", END).strip()
    if output_text_content:
        app.clipboard_clear()
        app.clipboard_append(output_text_content)
        app.update()
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    else:
        messagebox.showerror("Error", "No output to copy!")

# GUI setup
app = Tk()
app.title("Encryption & Decryption App")
app.geometry("450x500")
app.configure(bg="#e0f7fa")

# Title
Label(app, text="Encryption & Decryption Tool", font=("Arial", 16, "bold"), bg="#e0f7fa").pack(pady=10)

# Input Text
Label(app, text="Enter Text:", font=("Arial", 12), bg="#e0f7fa").pack()
text_entry = Text(app, height=4, width=40, wrap="word")
text_entry.pack(pady=5)

# Encryption Key
Label(app, text="Enter Encryption Key:", font=("Arial", 12), bg="#e0f7fa").pack()
encryption_key_entry = Entry(app, show="*", width=25)  # Masked entry
encryption_key_entry.pack(pady=5)

# Cipher Selection
Label(app, text="Select Cipher:", font=("Arial", 12), bg="#e0f7fa").pack()
cipher_var = StringVar(value="Base64")
cipher_menu = OptionMenu(app, cipher_var, "Base64", "DES", "AES")
cipher_menu.pack(pady=5)

# Buttons
frame_buttons = Frame(app, bg="#e0f7fa")
frame_buttons.pack(pady=10)
Button(frame_buttons, text="Encrypt", command=encrypt_text, bg="#00796b", fg="white", width=10).pack(side=LEFT, padx=5)
Button(frame_buttons, text="Decrypt", command=decrypt_text, bg="#00796b", fg="white", width=10).pack(side=LEFT, padx=5)

# Output Text
Label(app, text="Output:", font=("Arial", 12), bg="#e0f7fa").pack()
output_text = Text(app, height=4, width=40, state="disabled", wrap="word")
output_text.pack(pady=5)

# Copy to Clipboard Button
Button(app, text="Copy to Clipboard", command=copy_to_clipboard, bg="#00796b", fg="white", width=20).pack(pady=10)

app.mainloop()