import tkinter as tk
import numpy as np
import string
from tkinter import filedialog, messagebox

# === Fungsi Vigenere Cipher ===
def vigenere_encrypt(plaintext, key):
    alphabet = string.ascii_uppercase
    key = key.upper()
    plaintext = plaintext.upper()
    ciphertext = ''
    key_index = 0

    for letter in plaintext:
        if letter in alphabet:
            shift = alphabet.index(key[key_index % len(key)])
            index = (alphabet.index(letter) + shift) % 26
            ciphertext += alphabet[index]
            key_index += 1
        else:
            ciphertext += letter

    return ciphertext

def vigenere_decrypt(ciphertext, key):
    alphabet = string.ascii_uppercase
    key = key.upper()
    ciphertext = ciphertext.upper()
    plaintext = ''
    key_index = 0

    for letter in ciphertext:
        if letter in alphabet:
            shift = alphabet.index(key[key_index % len(key)])
            index = (alphabet.index(letter) - shift) % 26
            plaintext += alphabet[index]
            key_index += 1
        else:
            plaintext += letter

    return plaintext

# === Fungsi Playfair Cipher ===
def generate_playfair_square(key):
    # Menghapus duplikat, mengganti 'J' dengan 'I', dan memfilter non-alfabet
    key = key.upper().replace('J', 'I')  # Ganti J dengan I
    key = ''.join([char for char in key if char in string.ascii_uppercase])  # Hanya simpan huruf A-Z
    key = ''.join(sorted(set(key), key=key.index))  # Hapus duplikasi

    alphabet = string.ascii_uppercase.replace('J', '')  # Alphabet tanpa J
    square = [letter for letter in key if letter in alphabet]
    
    for letter in alphabet:
        if letter not in square:
            square.append(letter)
    
    return [square[i:i+5] for i in range(0, 25, 5)]

def find_position(letter, square):
    for row_idx, row in enumerate(square):
        if letter in row:
            return row_idx, row.index(letter)
    raise ValueError(f"{letter} is not in Playfair square.")

def preprocess_plaintext(plaintext):
    # Mengubah J menjadi I dan menghilangkan spasi
    plaintext = plaintext.upper().replace('J', 'I').replace(' ', '')
    processed_text = ''
    
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        # Menangani pasangan huruf yang sama dengan menyisipkan 'X'
        if i + 1 < len(plaintext) and plaintext[i] == plaintext[i + 1]:
            processed_text += a + 'X'
            i += 1
        else:
            b = plaintext[i + 1] if i + 1 < len(plaintext) else 'X'
            processed_text += a + b
            i += 2
    
    return processed_text


def playfair_encrypt(plaintext, key):
    square = generate_playfair_square(key)
    plaintext = preprocess_plaintext(plaintext)
    ciphertext = ''
    
    for i in range(0, len(plaintext), 2):
        a, b = plaintext[i], plaintext[i + 1]
        
        row_a, col_a = find_position(a, square)
        row_b, col_b = find_position(b, square)
        
        if row_a == row_b:
            ciphertext += square[row_a][(col_a + 1) % 5] + square[row_b][(col_b + 1) % 5]
        elif col_a == col_b:
            ciphertext += square[(row_a + 1) % 5][col_a] + square[(row_b + 1) % 5][col_b]
        else:
            ciphertext += square[row_a][col_b] + square[row_b][col_a]
    
    return ciphertext

def playfair_decrypt(ciphertext, key):
    square = generate_playfair_square(key)
    plaintext = ''
    
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        row_a, col_a = find_position(a, square)
        row_b, col_b = find_position(b, square)
        
        if row_a == row_b:
            plaintext += square[row_a][(col_a - 1) % 5] + square[row_b][(col_b - 1) % 5]
        elif col_a == col_b:
            plaintext += square[(row_a - 1) % 5][col_a] + square[(row_b - 1) % 5][col_b]
        else:
            plaintext += square[row_a][col_b] + square[row_b][col_a]
    
    return plaintext

def remove_placeholder_x(plaintext):
    cleaned_text = ''
    i = 0
    while i < len(plaintext):
        if i + 1 < len(plaintext) and plaintext[i + 1] == 'X' and (i + 2 >= len(plaintext) or plaintext[i] != plaintext[i + 2]):
            cleaned_text += plaintext[i]
            i += 2  # Lewati 'X'
        else:
            cleaned_text += plaintext[i]
            i += 1
    return cleaned_text


# === Fungsi Hill Cipher ===
def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("Inverse tidak ditemukan")

def matrix_mod_inverse(matrix, mod):
    det = int(np.round(np.linalg.det(matrix))) 
    if det == 0:
        raise ValueError("Determinant tidak boleh 0")
    det_inv = mod_inverse(det, mod)
    matrix_inv = np.round(det_inv * np.linalg.inv(matrix) * det).astype(int) % mod 
    return matrix_inv

def hill_encrypt(plaintext, key_matrix):
    plaintext = plaintext.upper().replace(" ", "")
    while len(plaintext) % 2 != 0:
        plaintext += 'X'
    
    plaintext_vector = [ord(char) - ord('A') for char in plaintext]
    ciphertext = ''

    for i in range(0, len(plaintext_vector), 2):
        block = np.array([[plaintext_vector[i]], [plaintext_vector[i + 1]]])
        encrypted_block = np.dot(key_matrix, block) % 26  # Enkripsi dengan matriks kunci
        ciphertext += chr(encrypted_block[0, 0] + ord('A')) + chr(encrypted_block[1, 0] + ord('A'))

    return ciphertext

def hill_decrypt(ciphertext, key_matrix):
    inv_key_matrix = matrix_mod_inverse(key_matrix, 26)
    ciphertext_vector = [ord(char) - ord('A') for char in ciphertext]
    plaintext = ''

    for i in range(0, len(ciphertext_vector), 2):
        block = np.array([[ciphertext_vector[i]], [ciphertext_vector[i + 1]]])
        decrypted_block = np.dot(inv_key_matrix, block) % 26 
        plaintext += chr(decrypted_block[0, 0] + ord('A')) + chr(decrypted_block[1, 0] + ord('A'))

    while plaintext.endswith('X'):
        plaintext = plaintext[:-1]

    return plaintext


# === Fungsi untuk memuat file ===
def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            teks_input.delete(1.0, tk.END)
            teks_input.insert(tk.END, file.read())

# === Fungsi untuk mengganti tampilan input keyword menjadi matriks untuk Hill Cipher ===
def switch_to_matrix_input():
    for widget in keyword_frame.winfo_children():
        widget.destroy()  # Menghapus widget yang ada di keyword_frame

    tk.Label(keyword_frame, text="Matriks Kunci (2x2):").grid(row=0, column=0, columnspan=2)

    # Matriks 2x2 untuk Hill Cipher
    global matrix_entries
    matrix_entries = [[tk.Entry(keyword_frame, width=5) for _ in range(2)] for _ in range(2)]
    
    for i in range(2):
        for j in range(2):
            matrix_entries[i][j].grid(row=i + 1, column=j)

# === Fungsi untuk mengganti tampilan input kembali ke kata kunci ===
def switch_to_keyword_input():
    for widget in keyword_frame.winfo_children():
        widget.destroy()  # Menghapus widget yang ada di keyword_frame

    tk.Label(keyword_frame, text="Kata Kunci:").grid(row=0, column=0, sticky='w')
    global keyword_entry
    keyword_entry = tk.Entry(keyword_frame, width=40)
    keyword_entry.grid(row=1, column=0, pady=10)

# === Fungsi utama untuk memilih metode cipher ===
def process_cipher():
    metode = cipher_method.get()
    
    if metode == "Vigenere":
        process_vigenere()
    elif metode == "Playfair":
        process_playfair()
    elif metode == "Hill":
        process_hill()

# === Fungsi untuk menjalankan enkripsi/dekripsi Hill Cipher ===
def process_hill():
    teks = teks_input.get(1.0, tk.END).strip()
    hasil_text.delete(1.0, tk.END)

    try:
        key_matrix = np.array([[int(matrix_entries[i][j].get()) for j in range(2)] for i in range(2)])
    except ValueError:
        messagebox.showwarning("Error", "Matriks kunci harus berisi angka.")
        return

    if mode.get() == 1:  # 1 untuk Enkripsi
        hasil = hill_encrypt(teks, key_matrix)
    else:  # 2 untuk Dekripsi
        hasil = hill_decrypt(teks, key_matrix)


    hasil_text.insert(tk.END, hasil)

# === Fungsi untuk Vigenere Cipher ===
def process_vigenere():
    teks = teks_input.get(1.0, tk.END).strip()
    key = keyword_entry.get()
    hasil_text.delete(1.0, tk.END)

    if len(key) < 12:
        messagebox.showwarning("Error", "Kata kunci harus minimal 12 karakter.")
        return

    if mode.get() == 1:
        hasil = vigenere_encrypt(teks, key)
    else:
        hasil = vigenere_decrypt(teks, key)

    hasil_text.insert(tk.END, hasil)

# === Fungsi untuk Playfair Cipher ===
def process_playfair():
    teks = teks_input.get(1.0, tk.END).strip()
    key = keyword_entry.get()
    hasil_text.delete(1.0, tk.END)

    if len(key) < 12:
        messagebox.showwarning("Error", "Kata kunci harus minimal 12 karakter.")
        return

    if mode.get() == 1:
        hasil = playfair_encrypt(teks, key)
    else:
        hasil = playfair_decrypt(teks, key)
        hasil = remove_placeholder_x(hasil)


    hasil_text.insert(tk.END, hasil)

# === GUI ===
root = tk.Tk()
root.title("Aplikasi Cipher")

# Frame utama
main_frame = tk.Frame(root)
main_frame.pack(pady=10)
keyword_frame = tk.Frame(main_frame)
keyword_frame.grid(row=5, column=0, pady=10)

# Label dan Dropdown untuk memilih metode
label_pilih_metode = tk.Label(main_frame, text="Pilih Metode Cipher:")
label_pilih_metode.grid(row=0, column=0, sticky='w')

cipher_method = tk.StringVar(value="Vigenere")
dropdown = tk.OptionMenu(main_frame, cipher_method, "Vigenere", "Playfair", "Hill")
dropdown.grid(row=1, column=0, pady=10)

# Label dan input teks
label_teks = tk.Label(main_frame, text="Masukkan teks:")
label_teks.grid(row=2, column=0, sticky='w')

teks_input = tk.Text(main_frame, height=5, width=40)
teks_input.grid(row=3, column=0, pady=10)

# Tombol untuk memuat teks dari file
load_button = tk.Button(main_frame, text="Muat dari file", command=load_file)
load_button.grid(row=4, column=0, pady=5)

# Radio button untuk memilih mode enkripsi/dekripsi
label_mode = tk.Label(main_frame, text="Pilih Mode:")
label_mode.grid(row=7, column=0, sticky='w')

radio_frame = tk.Frame(main_frame)
radio_frame.grid(row=8, column=0, pady=10)

mode = tk.IntVar(value=1)  # Default enkripsi
radio_encrypt = tk.Radiobutton(radio_frame, text="Enkripsi", variable=mode, value=1)
radio_encrypt.pack(side=tk.LEFT)

radio_decrypt = tk.Radiobutton(radio_frame, text="Dekripsi", variable=mode, value=2)
radio_decrypt.pack(side=tk.LEFT)

# Tombol untuk menjalankan proses
process_button = tk.Button(main_frame, text="Proses", command=process_cipher)
process_button.grid(row=9, column=0, pady=10)

# Label dan kolom hasil
label_hasil = tk.Label(main_frame, text="Hasil:")
label_hasil.grid(row=10, column=0, sticky='w')

hasil_text = tk.Text(main_frame, height=5, width=40)
hasil_text.grid(row=11, column=0, pady=10)

# Event handler saat memilih metode
def on_method_change(*args):
    metode = cipher_method.get()
    
    if metode == "Hill":
        switch_to_matrix_input()
    else:
        switch_to_keyword_input()

cipher_method.trace("w", on_method_change)

root.mainloop()