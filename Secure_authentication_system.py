import hashlib
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# Συνάρτηση για κατακερματισμό του κωδικού πρόσβασης με χρήση salt
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Δημιουργία τυχαίου salt
    hash_object = hashlib.md5(password.encode() + salt)
    return hash_object.hexdigest(), salt

# Συνάρτηση για αποθήκευση του κωδικού πρόσβασης σε αρχείο
def save_password(username, password):
    hashed_password, salt = hash_password(password)
    data = f"{hashed_password}\n{base64.b64encode(salt).decode()}"

    key = os.urandom(32)  # Κλειδί 256-bit για AES
    iv = os.urandom(16)   # IV για AES
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()

    with open(username + '.enc', 'wb') as file:
        file.write(iv + encrypted_data)  # Αποθήκευση IV + κρυπτογραφημένα δεδομένα

    return key  # Επιστρέφει το κλειδί για υπογραφή και επαλήθευση

# Συνάρτηση για φόρτωση και έλεγχο του κωδικού πρόσβασης από αρχείο
def load_password(username, password, key):
    with open(username + '.enc', 'rb') as file:
        iv = file.read(16)
        encrypted_data = file.read()

    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    stored_password_hash, stored_salt = decrypted_data.decode().split('\n')
    stored_salt = base64.b64decode(stored_salt)
    hashed_password, _ = hash_password(password, stored_salt)

    return stored_password_hash == hashed_password

# Συνάρτηση για υπογραφή του αρχείου κωδικών με ελλειπτικές καμπύλες
def sign_password_file(username, key):
    with open(username + '.enc', 'rb') as file:
        data = file.read()

    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    with open(username + '_signature.sig', 'wb') as sig_file:
        sig_file.write(signature)

    with open(username + '_key.key', 'wb') as key_file:
        key_file.write(key)

    with open(username + '_private_key.pem', 'wb') as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

# Συνάρτηση για επαλήθευση της υπογραφής του αρχείου κωδικών με ελλειπτικές καμπύλες
def verify_password_file_signature(username):
    with open(username + '.enc', 'rb') as file:
        data = file.read()

    with open(username + '_signature.sig', 'rb') as sig_file:
        signature = sig_file.read()

    with open(username + '_private_key.pem', 'rb') as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None
        )

    public_key = private_key.public_key()

    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

# Κύρια συνάρτηση για τον έλεγχο του κώδικα πρόσβασης και την επαλήθευση της υπογραφής
def authenticate_user(username, password):
    if not (os.path.exists(username + '.enc') and os.path.exists(username + '_key.key') and os.path.exists(username + '_signature.sig') and os.path.exists(username + '_private_key.pem')):
        print("Ο χρήστης δεν υπάρχει.")
        return

    with open(username + '_key.key', 'rb') as key_file:
        key = key_file.read()

    if load_password(username, password, key):
        if verify_password_file_signature(username):
            print("Επιτυχής σύνδεση.")
        else:
            print("Η υπογραφή δεν είναι έγκυρη.")
    else:
        print("Λάθος όνομα χρήστη ή κωδικός πρόσβασης.")

# Κύρια συνάρτηση για τη δημιουργία νέου χρήστη
def create_user():
    username = input("Εισάγετε όνομα χρήστη: ")
    password = input("Εισάγετε κωδικό πρόσβασης: ")
    key = save_password(username, password)
    sign_password_file(username, key)
    print("Ο νέος χρήστης δημιουργήθηκε επιτυχώς.")


# Κύρια λούπα προγράμματος
def main():
    while True:
        print("\nΚαλώς ήρθατε!\nΕπιλογές:")
        print("1. Σύνδεση")
        print("2. Δημιουργία νέου χρήστη")
        print("3. Έξοδος")
        choice = input("Επιλέξτε: ")

        if choice == '1':
            username = input("Εισάγετε όνομα χρήστη: ")
            password = input("Εισάγετε κωδικό πρόσβασης: ")
            authenticate_user(username, password)
        elif choice == '2':
            create_user()
        elif choice == '3':
            print("Αντίο!")
            break
        else:
            print("Μη έγκυρη επιλογή. Παρακαλώ προσπαθήστε ξανά.")

