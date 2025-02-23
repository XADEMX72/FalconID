import cv2
import face_recognition
import sqlite3
import numpy as np
import json
from cryptography.fernet import Fernet
import os

# Save the encryption key to a file
def save_key(key):
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)

# Load the encryption key from the file
def load_key():
    try:
        with open("encryption_key.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("Encryption key not found, generating a new key.")
        return Fernet.generate_key()

# Load or generate encryption key
KEY = load_key()

# Save the key if it was generated
if not os.path.exists("encryption_key.key"):
    save_key(KEY)

cipher = Fernet(KEY)

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, full_name TEXT, employee_number TEXT, face_encoding BLOB)''')
    conn.commit()
    return conn

# Convert OpenCV BGR frame to RGB
def bgr_to_rgb(frame):
    return cv2.cvtColor(frame, cv2.COLOR_BGR2RGB) if frame is not None else None

# Capture a face image
def capture_face():
    video_capture = cv2.VideoCapture(0)
    
    if not video_capture.isOpened():
        print("Error: Could not access webcam.")
        return None

    while True:
        ret, frame = video_capture.read()
        if not ret:
            print("Error: Could not capture image.")
            break
        
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        cv2.imshow('Video', frame)

        if cv2.waitKey(1) & 0xFF == ord('c'):
            break

    video_capture.release()
    cv2.destroyAllWindows()

    return rgb_frame

# Encrypt face encoding
def encrypt_data(data):
    return cipher.encrypt(data.encode())

# Decrypt face encoding
def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data).decode()

# Register a new user
def register_user(conn):
    full_name = input("Enter your full name: ")
    employee_number = input("Enter your employee number: ")

    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE employee_number = ?", (employee_number,))
    if c.fetchone():
        print("Error: Employee number already registered.")
        return

    print("Press 'c' to capture your face...")
    rgb_frame = capture_face()

    if rgb_frame is None:
        return

    face_encodings = face_recognition.face_encodings(rgb_frame)
    if not face_encodings:
        print("No face detected. Please try again.")
        return

    face_encoding_json = json.dumps(face_encodings[0].tolist())
    encrypted_encoding = encrypt_data(face_encoding_json)  # Encrypt the face encoding

    try:
        c.execute("INSERT INTO users (full_name, employee_number, face_encoding) VALUES (?, ?, ?)",
                  (full_name, employee_number, encrypted_encoding))
        conn.commit()
        print("✅ User registered successfully!")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

# Log in
def login(conn):
    employee_number = input("Enter your employee number: ")

    print("Press 'c' to capture your face...")
    rgb_frame = capture_face()

    if rgb_frame is None:
        return

    face_encodings = face_recognition.face_encodings(rgb_frame)
    if not face_encodings:
        print("No face detected. Please try again.")
        return

    c = conn.cursor()
    c.execute("SELECT face_encoding FROM users WHERE employee_number = ?", (employee_number,))
    result = c.fetchone()

    if not result:
        print("❌ Employee number not found.")
        return

    try:
        decrypted_encoding = decrypt_data(result[0])  # Decrypt stored encoding
        stored_encoding = np.array(json.loads(decrypted_encoding))
    except Exception as e:
        print(f"❌ Error decrypting face encoding: {e}")
        return

    input_encoding = face_encodings[0]
    distance = face_recognition.face_distance([stored_encoding], input_encoding)[0]
    match = distance < 0.4

    if match:
        print(f"✅ Access Approved (Match Confidence: {1 - distance:.2f})")
    else:
        print(f"❌ Access Denied (Match Confidence: {1 - distance:.2f})")

# Main menu
def main():
    conn = init_db()
    while True:
        print("\n1. Register a new user\n2. Log in\n3. Exit")
        choice = input("Choose an option: ")
        if choice == '1':
            register_user(conn)
        elif choice == '2':
            login(conn)
        elif choice == '3':
            break
    conn.close()

if __name__ == "__main__":
    main()
