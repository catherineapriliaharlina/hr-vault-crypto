import os
import time
import base64
from flask import Flask, render_template, request, send_from_directory, redirect, url_for, session
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = 'kunci_rahasia_hr_vault_sangat_aman'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Simpan riwayat benchmark
benchmark_logs = []
shared_requests = [] # Menyimpan data request kunci antar user

# Simulasi Database User dengan Pasangan Kunci RSA (Asimetris) & Password
# Setiap user otomatis dibuatkan RSA Key Pair (Public & Private Key)
users_db = {
    "hrd": {"pass": "rahasia123", "rsa_key": RSA.generate(2048)},
    "manager": {"pass": "manager123", "rsa_key": RSA.generate(2048)},
    "karyawan": {"pass": "karyawan123", "rsa_key": RSA.generate(2048)}
}

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users_db and users_db[username]["pass"] == password:
            session['user'] = username
            return redirect(url_for('index'))
        else:
            error = "Username atau Password salah! (Coba: hrd/rahasia123, manager/manager123)"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = session['user']
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    enc_files = [f for f in files if '.enc' in f]
    
    # Ambil daftar user lain untuk fitur Request Data
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
        
    file = request.files.get('file')
    if not file or file.filename == '':
        return redirect(url_for('index'))
        
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    file_size = os.path.getsize(filename=filepath)
    with open(filepath, 'rb') as f:
        plaintext = f.read()
        
    # Buat Kunci Simetris (AES) untuk mengenkripsi dokumen user
    aes_key = get_random_bytes_custom(16)
    
    start_time = time.time()
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    encrypted_data = cipher.iv + ciphertext
    elapsed_time = time.time() - start_time
    
    # Simpan log benchmark
    benchmark_logs.append({
        'filename': filename,
        'size': file_size,
        'cipher': 'AES-CBC',
        'time': round(elapsed_time, 6)
    })
    
    # Simpan file terenkripsi beserta kunci AES yang diamankan di metadata/file terpisah jika perlu
    # Untuk simpelnya, kita simpan file .enc
    encrypted_filename = f"{filename}.aes.enc"
    encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    with open(encrypted_filepath, 'wb') as f:
        f.write(aes_key + b":::" + encrypted_data) # Simpan AES key digabung di file (simulasi penyimpanan aman)
        
    os.remove(filepath)
    return redirect(url_for('index'))

@app.route('/request_data', methods=['POST'])
def request_data():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    target_user = request.form.get('target_user')
    requester = session['user']
    
    # Catat permintaan data
    shared_requests.append({
        'requester': requester,
        'target': target_user,
        'status': 'Pending'
    })
    return redirect(url_for('index'))

@app.route('/share_key/<target_requester>', methods=['POST'])
def share_key(target_requester):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Pemilik data mengenkripsi Kunci Simetris menggunakan Public Key dari Requester (Asymmetric Encryption)
    # Simulasi mengambil kunci AES dari file terenkripsi yang ada
    filename = request.form.get('file_to_share')
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return "File tidak ditemukan!"
        
    with open(filepath, 'rb') as f:
        content = f.read()
        aes_key = content.split(b":::")[0] # Ambil kunci AES asli
        
    # Enkripsi kunci AES dengan Public Key milik Requester (RSA-OAEP)
    requester_public_key = users_db[target_requester]['rsa_key'].publickey()
    cipher_rsa = PKCS1_OAEP.new(requester_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Encode ke Base64 agar gampang disalin via WA/Email/Web
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
    
    # Update status request
    for req in shared_requests:
        if req['requester'] == target_requester and req['target'] == session['user']:
            req['status'] = 'Approved'
            req['encrypted_key'] = encrypted_aes_key_b64
            req['filename'] = filename
            
    return redirect(url_for('index'))

@app.route('/decrypt_shared', methods=['POST'])
def decrypt_shared():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    current_user = session['user']
    encrypted_key_b64 = request.form.get('encrypted_key')
    filename = request.form.get('filename')
    
    try:
        # Dekripsi kunci AES menggunakan Private Key milik user yang sedang login (RSA Private Key)
        encrypted_aes_key = base64.b64decode(encrypted_key_b64)
        private_key = users_db[current_user]['rsa_key']
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        
        # Buka file terenkripsi
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'rb') as f:
            content = f.read()
            encrypted_data = content.split(b":::")[1]
            
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
        
        orig_filename = filename.replace('.aes.enc', '')
        decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], "shared_" + orig_filename)
        with open(decrypted_filepath, 'wb') as f:
            f.write(decrypted_data)
            
        return send_from_directory(app.config['UPLOAD_FOLDER'], "shared_" + orig_filename, as_attachment=True)
    except Exception as e:
        return f"Gagal mendekripsi kunci atau file! Error: {str(e)}"

def get_random_bytes_custom(n):
    return os.urandom(n)

if __name__ == '__main__':
    app.run(debug=True)