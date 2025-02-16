# BioCryptAuth 
 
## Features

- **Face Recognition**: Utilizes DeepFace for accurate user face recognition.
- **AES Encryption**: Secures password data with AES encryption for enhanced security.
- **Multi-Factor Authentication**: Combines biometric (face) and password-based authentication.
- **Real-time Verification**: Ensures fast and secure user identity verification.
- **Scalability**: Can be integrated into existing systems for user authentication.
- **Security**: Provides robust user authentication through the combination of cryptography and biometrics.

## Requirements

- Python 3.x
- DeepFace
- AES from PyCryptodome
- Flask or Django (if using a web interface)
- NumPy, OpenCV
- TensorFlow (if model training is required)


## Installation

1. Clone the repository:
   **git clone https://github.com/yourusername/BioCryptAuth.git**
2. Install the required packages:
   **pip install -r requirements.txt**
3. Set up the database (SQL/NoSQL) for storing user information.

## Usage
1. Train the DeepFace model or use pre-trained models for face recognition.
2. Register users with their face data and encrypted passwords.
3. Authenticate users by verifying their face and password.
4. Run the authentication server:
    **python app.py**


## System Architecture

The system architecture follows these core components:

1. **Face Recognition:** DeepFace is used for face recognition, ensuring only authorized users are allowed.

2. **Password Encryption:** AES encryption is used to securely store user passwords.

3. **Authentication Layer:** Verifies user credentials (face + password).

4. **Database:** Stores user data, encrypted passwords, and authentication logs.

## License
[MIT](https://choosealicense.com/licenses/mit/)
