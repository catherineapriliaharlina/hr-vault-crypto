import os
import time
import base64
from flask import Flask, render_template, request, send_from_directory, redirect, url_for, session
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = 'kunci_rahasia_hr_vault_sangat_aman'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# List penyimpanan sementara untuk log benchmark dan request akses
benchmark_logs = []
shared_requests = []

# Simulasi Database User & Pasangan Kunci RSA (Asimetris)
users_db = {
    "hrd": {"pass": "rahasia123", "rsa_key": RSA.generate(2048)},
    "manager": {"pass": "manager123", "rsa_key": RSA.generate(2048)},
    "karyawan": {"pass": "karyawan123", "rsa_key": RSA.generate(2048)}
}

@app.route('/login', methods=['GET', 'POST'])
def login():
    error_msg = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users_db and users_db[username]["pass"] == password:
            session['user'] = username
            return redirect(url_for('index'))
        else:
            error_msg = "Username atau password salah! Cek kembali kredensial Anda."
    return render_template('login.html', error=error_msg)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = session['user']
    all_files = os.listdir(app.config['UPLOAD_FOLDER'])
    enc_files = [f for f in all_files if '.enc' in f]
    
    other_users = [u for u in users_db.keys() if u != current_user]
    
    return render_template('dashboard.html', 
                           files=enc_files, 
                           logs=benchmark_logs, 
                           current_user=current_user,
                           other_users=other_users,
                           shared_requests=shared_requests)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    uploaded_file = request.files.get('file')
    if not uploaded_file or uploaded_file.filename == '':
        return redirect(url_for('index'))
        
    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    uploaded_file.save(filepath)
    
    file_size = os.path.getsize(filepath)
    with open(filepath, 'rb') as f:
        plaintext = f.read()
        
    # Generate kunci simetris AES acak (pas 16 bytes)
    aes_key = os.urandom(16)
    
    # Proses Enkripsi AES-CBC
    start_time = time.time()
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    encrypted_payload = cipher.iv + ciphertext
    elapsed_time = time.time() - start_time
    
    # Catat ke log benchmark
    benchmark_logs.append({
        'filename': filename,
        'size': file_size,
        'cipher': 'AES-CBC',
        'time': round(elapsed_time, 6)
    })
    
    # Simpan file terenkripsi dengan format pemisah ':::'
    encrypted_filename = f"{filename}.aes.enc"
    encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    with open(encrypted_filepath, 'wb') as f:
        f.write(aes_key + b":::" + encrypted_payload)
        
    os.remove(filepath)
    return redirect(url_for('index'))

@app.route('/request_data', methods=['POST'])
def request_data():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    target_user = request.form.get('target_user')
    requester = session['user']
    
    shared_requests.append({
        'requester': requester,
        'target': target_user,
        'status': 'Pending'
    })
    return redirect(url_for('index'))

@app.route('/share_key/<target_requester>/<int:req_id>', methods=['POST'])
def share_key(target_requester, req_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    filename = request.form.get('file_to_share')
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return "File target tidak ditemukan di server!"
        
    with open(filepath, 'rb') as f:
        content = f.read()
        
    if b":::" in content:
        aes_key = content.split(b":::")[0][:16]
    else:
        aes_key = b"Sixteen byte key"
        
    requester_public_key = users_db[target_requester]['rsa_key'].publickey()
    
    try:
        cipher_rsa = PKCS1_v1_5.new(requester_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    except Exception as e:
        return f"Gagal mengenkripsi kunci dengan RSA: {str(e)}"
    
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
    
    # Update data spesifik berdasarkan nomor baris (req_id) agar tidak saling menimpa
    if 0 <= req_id < len(shared_requests):
        shared_requests[req_id]['status'] = 'Approved'
        shared_requests[req_id]['encrypted_key'] = encrypted_aes_key_b64
        shared_requests[req_id]['filename'] = filename
            
    return redirect(url_for('index'))

@app.route('/decrypt_shared', methods=['POST'])
def decrypt_shared():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    current_user = session['user']
    encrypted_key_b64 = request.form.get('encrypted_key')
    filename = request.form.get('filename')
    
    try:
        # 1. Dekripsi kunci AES menggunakan Private Key RSA
        encrypted_aes_key = base64.b64decode(encrypted_key_b64.strip())
        private_key = users_db[current_user]['rsa_key']
        cipher_rsa = PKCS1_v1_5.new(private_key)
        
        sentinel = os.urandom(16)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key, sentinel)
        
        # 2. Baca file terenkripsi dari server dengan aman
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'rb') as f:
            content = f.read()
            
        if b":::" in content:
            encrypted_payload = content.split(b":::")[1]
        else:
            encrypted_payload = content
            
        iv = encrypted_payload[:16]
        ciphertext = encrypted_payload[16:]
        
        # 3. Dekripsi isi file menggunakan AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
        
        # 4. Kirim hasil dekripsi ke browser
        orig_filename = filename.replace('.aes.enc', '')
        decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], "shared_" + orig_filename)
        with open(decrypted_filepath, 'wb') as f:
            f.write(decrypted_data)
            
        return send_from_directory(app.config['UPLOAD_FOLDER'], "shared_" + orig_filename, as_attachment=True)
    except Exception as err:
        return f"Gagal mendekripsi file! Pastikan kunci RSA valid atau hak akses Anda sesuai. (Error: {str(err)})"

if __name__ == '__main__':
    app.run(debug=True)