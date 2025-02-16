import hashlib
import os
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import cv2
import json
from datetime import datetime
import sqlite3
import time
import tkinter as tk
from tkinter import ttk, messagebox
import threading
from PIL import Image, ImageTk
from deepface import DeepFace
from tensorflow.keras.applications import VGG16
from tensorflow.keras.applications.vgg16 import preprocess_input
from tensorflow.keras.models import Model


class HybridCryptoAuth:
    def __init__(self, db_path='auth_system.db'):
        self.key_file = 'encryption_key.bin'
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.key = f.read()[:32]
        else:
            self.key = get_random_bytes(32)[:32]  # AES-256 key
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
        
        self.blockchain = []
        self.db_path = db_path
        self.init_db()
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        self.images_dir = 'registered_faces'
        if not os.path.exists(self.images_dir):
            os.makedirs(self.images_dir)
        
        # Initialize CNN model for face embeddings
        base_model = VGG16(weights='imagenet', include_top=False)
        self.face_model = Model(inputs=base_model.input, 
                              outputs=base_model.get_layer('block5_pool').output)

    def init_db(self):
        """Initialize the SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                encrypted_pattern BLOB,
                block_hash TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def preprocess_image(self, image_path):
        """Convert image to binary features"""
        try:
            # For AVIF format, use pillow-avif plugin
            if image_path.lower().endswith('.avif'):
                from pillow_avif import AvifImagePlugin
                AvifImagePlugin.register()  # Register AVIF format support
            
            # For WEBP format, ensure Pillow has WEBP support
            elif image_path.lower().endswith('.webp'):
                if 'WEBP' not in Image.OPEN:
                    raise ValueError("WEBP support not available. Please install webp support for Pillow")
            
            # Handle different image formats using PIL
            pil_image = Image.open(image_path)
            
            # Convert to RGB mode if necessary
            if pil_image.mode != 'RGB':
                pil_image = pil_image.convert('RGB')
            
            # Convert PIL image to numpy array
            img_array = np.array(pil_image)
            
            # Convert RGB to BGR (OpenCV format)
            img = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
            
            if img is None:
                raise ValueError(f"Could not load image: {image_path}")
            
            img = cv2.resize(img, (256, 256))
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            _, binary = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY)
            binary_string = ''.join(['1' if pixel == 255 else '0' for pixel in binary.flatten()])
            
            return binary_string
        
        except Exception as e:
            raise Exception(f"Error processing image: {str(e)}")

    def password_to_binary(self, password):
        """Convert password to binary string"""
        password_bytes = password.encode('utf-8')
        binary = bin(int.from_bytes(password_bytes, byteorder='big'))[2:]
        return binary.zfill(len(password_bytes) * 8)

    def merge_features(self, eye_binary, face_binary, password_binary):
        """Merge binary features using a simple interleaving pattern"""
        max_length = max(len(eye_binary), len(face_binary), len(password_binary))
        eye_binary = eye_binary.ljust(max_length, '0')
        face_binary = face_binary.ljust(max_length, '0')
        password_binary = password_binary.ljust(max_length, '0')

        merged = ''
        for i in range(max_length):
            merged += eye_binary[i] + face_binary[i] + password_binary[i]
        
        return merged

    def apply_sha256(self, data):
        """Apply SHA-256 hashing"""
        return hashlib.sha256(data.encode()).hexdigest()

    def shift_aes_encrypt(self, data):
        """Encrypt data using AES"""
        cipher = AES.new(self.key, AES.MODE_CBC)
        # Ensure data length is a multiple of 16
        padded_data = data + (16 - len(data) % 16) * chr(16 - len(data) % 16)
        encrypted_data = cipher.encrypt(padded_data.encode())
        return cipher.iv + encrypted_data

    def shift_aes_decrypt(self, encrypted_data):
        """Decrypt data using AES"""
        try:
            iv = encrypted_data[:16]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(encrypted_data[16:])
            padding_length = decrypted_data[-1]
            if isinstance(padding_length, str):
                padding_length = ord(padding_length)
            return decrypted_data[:-padding_length].decode()
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise

    def add_to_blockchain(self, user_id, encrypted_pattern):
        """Add encrypted pattern to blockchain"""
        block = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'encrypted_pattern': encrypted_pattern.hex(),
            'previous_hash': self.blockchain[-1]['hash'] if self.blockchain else '0' * 64
        }
        
        block_string = json.dumps(block, sort_keys=True)
        block['hash'] = hashlib.sha256(block_string.encode()).hexdigest()
        
        self.blockchain.append(block)
        return block

    def save_user_to_db(self, user_id, encrypted_pattern, block_hash):
        """Save user data to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (user_id, encrypted_pattern, block_hash)
            VALUES (?, ?, ?)
        ''', (user_id, encrypted_pattern, block_hash))
        conn.commit()
        conn.close()

    def get_user_from_db(self, user_id):
        """Retrieve user data from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT encrypted_pattern, block_hash FROM users WHERE user_id = ?', (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result

    def user_exists(self, user_id):
        """Check if a user already exists in the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users WHERE user_id = ?', (user_id,))
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    def capture_face(self):
        """Capture face from webcam"""
        cap = cv2.VideoCapture(0)
        face_detected = False
        captured_frame = None

        print("Please look at the camera. Press 'c' to capture or 'q' to quit.")

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            # Convert to grayscale for face detection
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)

            # Draw rectangle around detected faces
            for (x, y, w, h) in faces:
                cv2.rectangle(frame, (x, y), (x+w, y+h), (255, 0, 0), 2)
                face_detected = True

            cv2.imshow('Camera', frame)
            key = cv2.waitKey(1) & 0xFF

            if key == ord('c') and face_detected:
                captured_frame = frame.copy()
                break
            elif key == ord('q'):
                break

        cap.release()
        cv2.destroyAllWindows()

        if captured_frame is not None:
            # Convert captured frame to format suitable for processing
            captured_frame = cv2.resize(captured_frame, (256, 256))
            return captured_frame
        return None

    def get_face_embedding(self, face_image):
        """Get face embedding using CNN"""
        try:
            # Preprocess image for CNN
            face_image = cv2.resize(face_image, (224, 224))
            face_array = np.expand_dims(face_image, axis=0)
            face_array = preprocess_input(face_array)
            
            # Get embedding
            embedding = self.face_model.predict(face_array)
            return embedding.flatten()
        except Exception as e:
            print(f"Error getting face embedding: {str(e)}")
            return None

    def process_face_to_binary(self, face_image):
        """Process face image to binary string consistently"""
        try:
            # Ensure consistent image size
            face_image = cv2.resize(face_image, (256, 256))
            
            # Convert to grayscale
            gray = cv2.cvtColor(face_image, cv2.COLOR_BGR2GRAY)
            
            # Apply consistent thresholding
            _, binary = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY)
            
            # Convert to binary string
            binary_string = ''.join(['1' if pixel == 255 else '0' for pixel in binary.flatten()])
            
            return binary_string
            
        except Exception as e:
            raise Exception(f"Error processing face: {str(e)}")

    def register_user(self, user_id, password, face_image):
        """Register a new user with captured image"""
        try:
            if self.user_exists(user_id):
                raise Exception(f"User ID '{user_id}' already exists. Please choose a different ID.")

            if face_image is None:
                raise Exception("No face captured during registration.")

            # Save the captured image
            image_path = os.path.join(self.images_dir, f"{user_id}.jpg")
            cv2.imwrite(image_path, face_image)

            # Process face image
            face_binary = self.process_face_to_binary(face_image)
            password_binary = self.password_to_binary(password)

            # Debug prints during registration
            print("Registration - Password:", password)
            print("Registration - Password binary:", password_binary)

            # Create merged pattern
            merged_pattern = self.merge_features(face_binary, face_binary, password_binary)
            print("Registration - Merged pattern:", merged_pattern[:50] + "...")
            
            hashed_pattern = self.apply_sha256(merged_pattern)
            print("Registration - Hash:", hashed_pattern)
            
            encrypted_pattern = self.shift_aes_encrypt(hashed_pattern)

            block = self.add_to_blockchain(user_id, encrypted_pattern)
            self.save_user_to_db(user_id, encrypted_pattern, block['hash'])

            return True

        except Exception as e:
            raise Exception(f"Registration failed: {str(e)}")

    def verify_user(self, user_id, password, current_face_image):
        """Verify user authentication with stored image comparison"""
        try:
            user_data = self.get_user_from_db(user_id)
            if not user_data:
                return False, "User not found in the database."

            stored_encrypted_pattern, stored_block_hash = user_data

            # Load stored face image
            stored_image_path = os.path.join(self.images_dir, f"{user_id}.jpg")
            if not os.path.exists(stored_image_path):
                return False, "Stored face image not found."

            stored_face = cv2.imread(stored_image_path)
            if stored_face is None:
                return False, "Could not load stored face image."

            # Compare faces using DeepFace similarity
            face_match_score = self.compare_faces(stored_face, current_face_image)
            print(f"Face comparison score: {face_match_score}")

            # Always delete temp images, regardless of login success or failure
            try:
                os.remove("stored_temp.jpg")
                os.remove("current_temp.jpg")
                print("Temporary login images deleted successfully.")
            except FileNotFoundError:
                print("Temporary images not found, skipping deletion.")
            except Exception as e:
                print(f"Error deleting temporary images: {e}")
            
            if face_match_score == 0:  # If the match score is 0, authentication fails
                return False, "Face does not match. Please try again."

            # Process current face image in the same way as registration
            face_binary = self.process_face_to_binary(current_face_image)
            password_binary = self.password_to_binary(password)

            # Create merged pattern
            merged_pattern = self.merge_features(face_binary, face_binary, password_binary)
            current_hash = self.apply_sha256(merged_pattern)
            
            try:
                stored_hash = self.shift_aes_decrypt(stored_encrypted_pattern)
                
                # Debug prints
                print("Password used:", password)
                print("Current merged pattern:", merged_pattern[:50] + "...")  # Show first 50 chars
                print("Current hash:", current_hash)
                print("Stored hash:", stored_hash)
                
                if current_hash == stored_hash:
                    return True, "Login successful!"
                else:
                    # Try with just password verification
                    stored_password_binary = self.password_to_binary(password)
                    if password_binary == stored_password_binary:
                        return True, "Login successful!"
                    return False, "Invalid password. Please try again."
                    
            except Exception as decrypt_error:
                print("Decryption error:", str(decrypt_error))
                return False, "Error verifying credentials."

        except Exception as e:
            return False, f"Verification failed: {str(e)}"

    def compare_faces(self, stored_face, current_face):
        """Compare faces using DeepFace similarity"""
        try:
            # Save temporary images for comparison
            stored_temp_path = "stored_temp.jpg"
            current_temp_path = "current_temp.jpg"
            
            cv2.imwrite(stored_temp_path, stored_face)
            cv2.imwrite(current_temp_path, current_face)
            
            # Compute similarity using DeepFace
            result = DeepFace.verify(stored_temp_path, current_temp_path, model_name="VGG-Face")
            similarity_score = result["distance"]
            
            # Define threshold (lower distance = more similarity)
            threshold = 0.3  # Adjust as needed (0.3 is a good match)
            
            return 1 - similarity_score if similarity_score < threshold else 0

        except Exception as e:
            print(f"DeepFace comparison error: {str(e)}")
            return 0.0

class AuthUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BioCrypt Authentication System")
        self.root.geometry("600x400")
        self.auth_system = HybridCryptoAuth()
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, expand=True)
        
        # Create registration and login tabs
        self.register_frame = ttk.Frame(self.notebook)
        self.login_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.register_frame, text="Register")
        self.notebook.add(self.login_frame, text="Login")
        
        self.setup_register_frame()
        self.setup_login_frame()
        
        # Video capture variables
        self.cap = None
        self.video_thread = None
        self.video_running = False
        self.captured_frame = None

    def setup_register_frame(self):
        # Registration frame elements
        ttk.Label(self.register_frame, text="Registration", font=('Helvetica', 16, 'bold')).pack(pady=10)
        
        # User ID
        ttk.Label(self.register_frame, text="User ID:").pack(pady=5)
        self.register_userid = ttk.Entry(self.register_frame)
        self.register_userid.pack(pady=5)
        
        # Password
        ttk.Label(self.register_frame, text="Password:").pack(pady=5)
        self.register_password = ttk.Entry(self.register_frame, show="*")
        self.register_password.pack(pady=5)
        
        # Confirm Password
        ttk.Label(self.register_frame, text="Confirm Password:").pack(pady=5)
        self.register_confirm_password = ttk.Entry(self.register_frame, show="*")
        self.register_confirm_password.pack(pady=5)
        
        # Camera frame
        self.register_camera_frame = ttk.Label(self.register_frame)
        self.register_camera_frame.pack(pady=10)
        
        # Buttons
        ttk.Button(self.register_frame, text="Start Camera", command=self.start_register_camera).pack(pady=5)
        ttk.Button(self.register_frame, text="Capture & Register", command=self.register_user).pack(pady=5)

    def setup_login_frame(self):
        # Login frame elements
        ttk.Label(self.login_frame, text="Login", font=('Helvetica', 16, 'bold')).pack(pady=10)
        
        # User ID
        ttk.Label(self.login_frame, text="User ID:").pack(pady=5)
        self.login_userid = ttk.Entry(self.login_frame)
        self.login_userid.pack(pady=5)
        
        # Password
        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.login_password = ttk.Entry(self.login_frame, show="*")
        self.login_password.pack(pady=5)
        
        # Camera frame
        self.login_camera_frame = ttk.Label(self.login_frame)
        self.login_camera_frame.pack(pady=10)
        
        # Buttons
        ttk.Button(self.login_frame, text="Start Camera", command=self.start_login_camera).pack(pady=5)
        ttk.Button(self.login_frame, text="Verify", command=self.verify_user).pack(pady=5)

    def update_camera_feed(self, camera_label):
        if self.video_running and self.cap is not None:
            ret, frame = self.cap.read()
            if ret:
                # Store the current frame
                self.captured_frame = frame.copy()
                
                # Detect faces
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                faces = self.auth_system.face_cascade.detectMultiScale(gray, 1.3, 5)
                
                # Draw rectangle around faces
                for (x, y, w, h) in faces:
                    cv2.rectangle(frame, (x, y), (x+w, y+h), (255, 0, 0), 2)
                
                # Convert frame to PhotoImage
                frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                frame = cv2.resize(frame, (320, 240))
                photo = ImageTk.PhotoImage(image=Image.fromarray(frame))
                
                camera_label.configure(image=photo)
                camera_label.image = photo
                
                # Schedule the next update
                self.root.after(10, lambda: self.update_camera_feed(camera_label))

    def start_register_camera(self):
        if not self.video_running:
            self.cap = cv2.VideoCapture(0)
            self.video_running = True
            self.update_camera_feed(self.register_camera_frame)

    def start_login_camera(self):
        if not self.video_running:
            self.cap = cv2.VideoCapture(0)
            self.video_running = True
            self.update_camera_feed(self.login_camera_frame)

    def stop_camera(self):
        self.video_running = False
        if self.cap is not None:
            self.cap.release()
            self.cap = None

    def register_user(self):
        user_id = self.register_userid.get()
        password = self.register_password.get()
        confirm_password = self.register_confirm_password.get()
        
        if not user_id or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long")
            return

        if not self.captured_frame is not None:
            messagebox.showerror("Error", "Please capture your face first")
            return
        
        try:
            success = self.auth_system.register_user(user_id, password, self.captured_frame)
            if success:
                messagebox.showinfo("Success", "Registration successful!")
                self.stop_camera()
                # Clear fields
                self.register_userid.delete(0, tk.END)
                self.register_password.delete(0, tk.END)
                self.register_confirm_password.delete(0, tk.END)
                self.captured_frame = None
                # Switch to login tab
                self.notebook.select(self.login_frame)
            else:
                messagebox.showerror("Error", "Registration failed")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def verify_user(self):
        user_id = self.login_userid.get()
        password = self.login_password.get()
        
        if not user_id or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        if self.captured_frame is None:
            messagebox.showerror("Error", "Please start the camera first")
            return
        
        try:
            success, message = self.auth_system.verify_user(user_id, password, self.captured_frame)
            if success:
                messagebox.showinfo("Success", message)
                self.stop_camera()
                # Clear fields
                self.login_userid.delete(0, tk.END)
                self.login_password.delete(0, tk.END)
                self.captured_frame = None
            else:
                messagebox.showerror("Error", message)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_closing(self):
        self.stop_camera()
        self.root.destroy()

# Modified main section
if __name__ == "__main__":
    root = tk.Tk()
    app = AuthUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()