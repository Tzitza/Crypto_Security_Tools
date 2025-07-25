import hashlib

def calculate_hashes(file_path):
    hashes = {}
    with open(file_path, 'rb') as file:
        data = file.read()
        # Calculate MD5 hash
        md5_hash = hashlib.md5(data).hexdigest()
        hashes['MD5'] = md5_hash

        # Calculate SHA-1 hash
        sha1_hash = hashlib.sha1(data).hexdigest()
        hashes['SHA-1'] = sha1_hash

        # Calculate SHA-256 hash
        sha256_hash = hashlib.sha256(data).hexdigest()
        hashes['SHA-256'] = sha256_hash

        # Calculate Keccak (SHA-3) hash
        keccak_hash = hashlib.sha3_256(data).hexdigest()
        hashes['Keccak(SHA3)'] = keccak_hash

    return hashes

def check_integrity(file_path):
    original_hashes = calculate_hashes(file_path)
    
    print("Original Hashes:")
    for algo, value in original_hashes.items():
        print(f"{algo}: {value}")

    # Modify the file to simulate tampering
    with open(file_path, 'ab') as file:
        file.write(b'Tampered Data')

    modified_hashes = calculate_hashes(file_path)
    
    print("\nModified Hashes:")
    for algo, value in modified_hashes.items():
        print(f"{algo}: {value}")

    # Check if any hash has changed
    integrity_check = True
    for algo, original_hash in original_hashes.items():
        modified_hash = modified_hashes.get(algo)
        if modified_hash != original_hash:
            print(f"\nIntegrity Check Failed! {algo} hash has changed.")
            integrity_check = False
    
    if integrity_check:
        print("\nIntegrity Check Passed! File has not been tampered with.")
    else:
        print("\nIntegrity Check Failed! File has been tampered with.")

def save_hashes_to_file(file_path, hashes):
    with open(file_path, 'w') as file:
        for algo, value in hashes.items():
            file.write(f"{algo}: {value}\n")

if __name__ == "__main__":
    # Ask for the file path
    file_path = input("Enter path to the file: ")

    # Calculate hashes
    file_hashes = calculate_hashes(file_path)

    # Save original hashes to a separate file
    original_hashes_file = "original_hashes.txt"
    save_hashes_to_file(original_hashes_file, file_hashes)
    print(f"Original hashes saved to {original_hashes_file}")

    # Check integrity
    check_integrity(file_path)

    # Ask if user wants to save modified hashes
    save_modified_hashes = input("Do you want to save modified hashes to a file? (y/n): ").strip().lower()
    if save_modified_hashes == "y":
        modified_hashes_file = "modified_hashes.txt"
        save_hashes_to_file(modified_hashes_file, file_hashes)
        print(f"Modified hashes saved to {modified_hashes_file}")
