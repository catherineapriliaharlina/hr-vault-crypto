import os
import time
from flask import Flask, render_template, request, send_from_directory, redirect, url_for, session
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = 'kunci_rahasia_hr_vault_sangat_aman' # Dibutuhkan untuk session login
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Kunci rahasia cipher
AES_KEY = b'Sixteen byte key'  # 16 bytes
DES_KEY = b'8bytekey'          # 8 bytes
RC4_KEY = b'mysecretkeyrc4'    # RC4 key

# Simpan riwayat benchmark sementara di memory (untuk bahan laporan)
benchmark_logs = []

# Akun dummy HRD untuk autentikasi
HRD_USER = "hrd"
HRD_PASS = "rahasia123"

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == HRD_USER and password == HRD_PASS:
            session['user'] = username
            return redirect(url_for('index'))
        else:
            error = "Username atau Password salah!"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    # Syarat: Hanya pengguna terautentikasi yang boleh akses
    if 'user' not in session:
        return redirect(url_for('login'))
    
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    # Filter hanya file terenkripsi (.enc)
    enc_files = [f for f in files if '.enc' in f]
    return render_template('dashboard.html', files=enc_files, logs=benchmark_logs)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    if 'file' not in request.files:
        return redirect(url_for('index'))
    
    file = request.files['file']
    cipher_type = request.form.get('cipher') # 'aes', 'des', atau 'rc4'
    
    if file.filename == '':
        return redirect(url_for('index'))
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        file_size = os.path.getsize(filepath) # Ukuran file dalam bytes
        
        with open(filepath, 'rb') as f:
            plaintext = f.read()
            
        # Mulai ukur waktu enkripsi (Benchmark)
        start_time = time.time()
        
        if cipher_type == 'aes':
            cipher = AES.new(AES_KEY, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            encrypted_data = cipher.iv + ciphertext
        elif cipher_type == 'des':
            cipher = DES.new(DES_KEY, DES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
            encrypted_data = cipher.iv + ciphertext
        elif cipher_type == 'rc4':
            cipher = ARC4.new(RC4_KEY)
            encrypted_data = cipher.encrypt(plaintext)
        else:
            return "Cipher tidak valid!"
            
        elapsed_time = time.time() - start_time
        
        # Simpan log benchmark untuk analisis laporan
        benchmark_logs.append({
            'filename': filename,
            'size': file_size,
            'cipher': cipher_type.upper(),
            'time': round(elapsed_time, 6)
        })
        
        # Simpan file terenkripsi
        encrypted_filename = f"{filename}.{cipher_type}.enc"
        encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        with open(encrypted_filepath, 'wb') as f:
            f.write(encrypted_data)
            
        # Hapus file mentah asli
        os.remove(filepath)
        
        return redirect(url_for('index'))

@app.route('/decrypt/<filename>')
def decrypt_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
        
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    with open(filepath, 'rb') as f:
        encrypted_data = f.read()
        
    if '.aes.enc' in filename:
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        original_filename = filename.replace('.aes.enc', '')
    elif '.des.enc' in filename:
        iv = encrypted_data[:8]
        ciphertext = encrypted_data[8:]
        cipher = DES.new(DES_KEY, DES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), DES.block_size)
        original_filename = filename.replace('.des.enc', '')
    elif '.rc4.enc' in filename:
        cipher = ARC4.new(RC4_KEY)
        decrypted_data = cipher.decrypt(encrypted_data)
        original_filename = filename.replace('.rc4.enc', '')
    else:
        return "Format file tidak dikenal!"
        
    decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], "decrypted_" + original_filename)
    with open(decrypted_filepath, 'wb') as f:
        f.write(decrypted_data)
        
    return send_from_directory(app.config['UPLOAD_FOLDER'], "decrypted_" + original_filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)