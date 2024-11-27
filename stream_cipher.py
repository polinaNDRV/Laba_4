import tkinter as tk
from tkinter import messagebox
import hashlib
import secrets


def XOR_C(key_bytes, data):
    if key_bytes is None:
        raise ValueError("Ключ не может быть None")
    if data is None:
        raise ValueError("Данные не могут быть None")

    round = 0
    gamma = 0
    round_gamma = None
    if isinstance(data, str):
        data = data.encode('utf-8')

    for d in data:
        if gamma == 0:
            counter_block = key_bytes + round.to_bytes(8, 'big')
            round_gamma = hashlib.sha512(counter_block).digest()

        yield (d ^ round_gamma[gamma])

        if gamma < len(round_gamma) - 1:
            gamma += 1
        else:
            gamma = 0
            round += 1

def generate_key(length=64):
    return secrets.token_bytes(length)


def encrypt_text():
    plaintext = plaintext_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    if not key or not plaintext:
        messagebox.showerror("Ошибка", "Пожалуйста, введите и текст, и ключ.")
        return
    key_bytes = key.encode('utf-8')
    encrypted_bytes = bytearray(XOR_C(key_bytes, plaintext))
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

    decrypted_bytes = bytearray(XOR_C(key_bytes, ciphertext))

    decrypted_text_entry.delete("1.0", tk.END)
    decrypted_text_entry.insert(tk.END, decrypted_bytes.decode('utf-8', errors='ignore'))


def generate_key_and_display():
    key = generate_key()
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key.hex())

root = tk.Tk()
root.title("Поточный шифр (CTR)")

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
import tkinter as tk
from tkinter import messagebox
import hashlib
import secrets


def XOR_C(key_bytes, data):
    if key_bytes is None:
        raise ValueError("Ключ не может быть None")
    if data is None:
        raise ValueError("Данные не могут быть None")

    round = 0
    gamma = 0
    round_gamma = None
    if isinstance(data, str):
        data = data.encode('utf-8')

    for d in data:
        if gamma == 0:
            counter_block = key_bytes + round.to_bytes(8, 'big')
            round_gamma = hashlib.sha512(counter_block).digest()

        yield (d ^ round_gamma[gamma])

        if gamma < len(round_gamma) - 1:
            gamma += 1
        else:
            gamma = 0
            round += 1

def generate_key(length=64):
    return secrets.token_bytes(length)


def encrypt_text():
    plaintext = plaintext_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    if not key or not plaintext:
        messagebox.showerror("Ошибка", "Пожалуйста, введите и текст, и ключ.")
        return
    key_bytes = key.encode('utf-8')
    encrypted_bytes = bytearray(XOR_C(key_bytes, plaintext))
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

    decrypted_bytes = bytearray(XOR_C(key_bytes, ciphertext))

    decrypted_text_entry.delete("1.0", tk.END)
    decrypted_text_entry.insert(tk.END, decrypted_bytes.decode('utf-8', errors='ignore'))


def generate_key_and_display():
    key = generate_key()
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key.hex())

root = tk.Tk()
root.title("Поточный шифр (CTR)")

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
