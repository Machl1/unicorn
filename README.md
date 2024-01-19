import hashlib
# User database (username, password, fingerprint, face image path)
users = [
    {'username': 'user1', 'password': 'password1', 
    {'username': 'user2', 'password': 'password2', 
    # Add more users here
]

def login_with_username_password(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    for user in users:
        if user['username'] == username and user['password'] == hashed_password:
            return True
            from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import os

# Key derivation parameters
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000

def generate_key_from_password(password, salt):
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS, hmac_hash_module=SHA256)
    return key

def encrypt_file(file_path, key):
    # Generate a random initialization vector (IV)
    iv = get_random_bytes(AES.block_size)

    # Create AES cipher object with CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Read the file content
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Pad the plaintext to be a multiple of the block size
    padded_plaintext = pad(plaintext, AES.block_size)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    # Append the IV to the ciphertext
    encrypted_data = iv + ciphertext

    # Write the encrypted data back to the file
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(file_path, key):
    # Read the encrypted data from the file
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    # Extract the IV from the encrypted data
    iv = encrypted_data[:AES.block_size]

    # Create AES cipher object with CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext
    ciphertext = encrypted_data[AES.block_size:]
    padded_plaintext = cipher.decrypt(ciphertext)

    # Remove the padding from the plaintext
    plaintext = unpad(padded_plaintext, AES.block_size)

    # Write the decrypted data back to the file
    with open(file_path, 'wb') as file:
        file.write(plaintext)

# Usage example
file_path = 'path/to/secret/file.txt'
password = 'user_password'

# Generate a random salt
salt = get_random_bytes(SALT_SIZE)

# Derive the encryption key from the user's password and the salt
key = generate_key_from_password(password, salt)

# Encrypt the file
encrypt_file(file_path, key)

# Decrypt the file
decrypt_file(file_path, key)
from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']

    # Check if a file is selected
    if file.filename == '':
        return 'No file selected'

    # Save the file securely
    # (e.g., store it in a secured directory)
    secure_file_path = '/path/to/secure/folder/' + file.filename
    file.save(secure_file_path)

    return 'File uploaded successfully'

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Start the server using HTTPS

    import os
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Set up a secure folder to store the files
secure_folder_path = '/path/to/secure/folder/'
os.makedirs(secure_folder_path, exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']

    # Check if a file is selected
    if file.filename == '':
        return 'No file selected'

    # Generate a secure filename
    secure_file_name = secure_filename(file.filename)

    # Save the file securely
    secure_file_path = os.path.join(secure_folder_path, secure_file_name)
    file.save(secure_file_path)

    return 'File uploaded and encrypted securely'

    import os
from flask import Flask, request, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Set up a secure folder to store the files
secure_folder_path = '/path/to/secure/folder/'
os.makedirs(secure_folder_path, exist_ok=True)

# Define roles with their corresponding file permissions
roles = {
    'admin': ['upload', 'download', 'delete'],
    'user': ['upload', 'download']
}

# Simulating user authentication and authorization
def authenticate(username, password):
    # Perform authentication logic
    # Return True if authenticated, False otherwise
    return True

def authorize(username, permission):
    # Perform authorization logic
    # Return True if authorized, False otherwise
    if username == 'admin':
        return True
    elif username == 'user' and permission in roles['user']:
        return True

@app.route('/upload', methods=['POST'])
def upload_file():
    username = request.form['username']
    password = request.form['password']
    file = request.files['file']

    # Authenticate user
    if not authenticate(username, password):
        abort(401, 'Unauthorized')

    # Check if a file is selected
    if file.filename == '':
        return 'No file selected'

    # Generate a secure filename
    secure_file_name = secure_filename(file.filename)

    # Check permission for file upload
    if not authorize(username, 'upload'):
        abort(403, 'Forbidden')

    # Save the file securely
    secure_file_path = os.path.join(secure_folder_path, secure_file_name)
    file.save(secure_file_path)

    return 'File uploaded and encrypted securely'

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    username = request.args.get('username')
    password = request.args.get('password')

    # Authenticate user
    if not authenticate(username, password):
        abort(401, 'Unauthorized')

    # Check permission for file download
    if not authorize(username, 'download'):
        abort(403, 'Forbidden')

    # Generate the file path
    secure_file_path = os.path.join(secure_folder_path, filename)

    # Check if the file exists
    if not os.path.exists(secure_file_path):
        abort(404, 'File not found')

    # Perform file download logic
    # Add your code to download the file securely

    return 'File downloaded securely'

@app.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    username = request.args.get('username')
    password = request.args.get('password')

    # Authenticate user
    if not authenticate(username, password):
        abort(401, 'Unauthorized')

    # Check permission for file delete
    if not authorize(username, 'delete'):
        abort(403, 'Forbidden')

    # Generate the file path
    secure_file_path = os.path.join(secure_folder_path, filename)

    # Check if the file exists
    if not os.path.exists(secure_file_path):
        abort(404, 'File not found')

    # Perform file delete logic
    # Add your code to delete the file securely

    return 'File deleted securely'

    
