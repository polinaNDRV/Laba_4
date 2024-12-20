import tkinter as tk
from tkinter import messagebox
import secrets

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    key_length = len(key)

    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]

  # Гамма
    i = j = 0
    output = bytearray()

    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        output.append(byte ^ K)

    return bytes(output)

def encrypt_text():
    plaintext = plaintext_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    if not key or not plaintext:
        messagebox.showerror("Ошибка", "Пожалуйста, введите и текст, и ключ.")
        return

    key_bytes = key.encode('utf-8')
    encrypted_bytes = rc4(key_bytes, plaintext.encode('utf-8'))
    encrypted_text_entry.delete("1.0", tk.END)
    encrypted_text_entry.insert(tk.END, encrypted_bytes.hex())

def decrypt_text():
    ciphertext_hex = encrypted_text_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    if not key or not ciphertext_hex:
        messagebox.showerror("Ошибка", "Пожалуйста, введите и текст, и ключ.")
        return

    key_bytes = key.encode('utf-8')
    ciphertext = bytes.fromhex(ciphertext_hex)
    decrypted_bytes = rc4(key_bytes, ciphertext)

    decrypted_text_entry.delete("1.0", tk.END)
    decrypted_text_entry.insert(tk.END, decrypted_bytes.decode('utf-8', errors='ignore'))

def generate_key_and_display():
    key = secrets.token_bytes(16)  # Ключ
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key.hex())

root = tk.Tk()
root.title("Поточный шифр (RC4)")

plaintext_label = tk.Label(root, text="Исходный текст:")
plaintext_label.pack()
plaintext_entry = tk.Text(root, height=5, width=50)
plaintext_entry.pack()

key_label = tk.Label(root, text="Ключ (для шифрования и дешифрования):")
key_label.pack()
key_entry = tk.Entry(root, width=50)
key_entry.pack()

generate_key_button = tk.Button(root, text="Сгенерировать случайный ключ", command=generate_key_and_display)
generate_key_button.pack()

encrypt_button = tk.Button(root, text="Зашифровать", command=encrypt_text)
encrypt_button.pack()

encrypted_text_label = tk.Label(root, text="Зашифрованный текст (в шестнадцатеричном виде):")
encrypted_text_label.pack()
encrypted_text_entry = tk.Text(root, height=5, width=50)
encrypted_text_entry.pack()

decrypt_button = tk.Button(root, text="Дешифровать", command=decrypt_text)
decrypt_button.pack()

decrypted_text_label = tk.Label(root, text="Дешифрованный текст:")
decrypted_text_label.pack()
decrypted_text_entry = tk.Text(root, height=5, width=50)
decrypted_text_entry.pack()

root.mainloop()