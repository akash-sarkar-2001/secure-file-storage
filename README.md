# Secure File Storage with Access Control

## Overview

This project is a Secure File Storage system designed to prioritize confidentiality, integrity, and access control. It uses a combination of modern technologies and security practices to protect user files, control sharing, and provide transparent, tamper-proof activity logging.

## Features

- **User & Admin Authentication with 2FA:** Strong authentication for both users and administrators, including two-factor authentication.
- **AES Encryption:** All files are encrypted before storage to maintain confidentiality.
- **Role-Based Access Control (RBAC):** Permissions and roles are enforced for users and administrators.
- **Secure File Sharing:** Users can share files with other users, specifying permissions and expiration.
- **Temporary Access Control:** Grant or revoke access to shared files at any time.
- **Blockchain-Based Logging:** All significant actions are logged on an internal blockchain for transparency and auditability.
- **SHA-256 Integrity Verification:** Ensures files have not been tampered with.
- **Real-Time Alerts:** Users receive notifications for important events like uploads and shares.
- **Admin Panel:** Administrators can manage users, files, and view system-wide logs.

## System Architecture

- **Backend:** Flask (Python)
- **Frontend:** HTML/CSS/Jinja2 templates (Flask)
- **Database:** MongoDB
- **Encryption:** AES for files, SHA-256 for integrity
- **Virtualization:** Runs on Kali Linux inside VirtualBox on a VPS

## Minimum System Requirements

- **CPU:** Dual-core 2.0 GHz or higher
- **RAM:** 4 GB (8 GB recommended)
- **Storage:** 20 GB free disk space
- **Operating System:** Kali Linux (in VirtualBox), host OS can be Windows, Linux, or macOS
- **Network:** Stable internet connection
- **Additional Software:** Python 3.8+, pip, Flask, MongoDB, OpenSSH/SFTP server, required Python libraries (see `requirements.txt`)
- **Web Browser:** Modern browser for user access

## Installation

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/akash-sarkar-2001/secure-file-storage.git
    cd secure-file-storage
    ```

2. **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3. **Set Up MongoDB:**
    - Install MongoDB and start the service.

4. **Configure Environment Variables:**
    - Set up environment variables as required (e.g., Flask SECRET_KEY, MongoDB URI).

5. **Start the Application:**
    ```bash
    python test.py
    ```

6. **Access the System:**
    - Open your web browser and go to `http://localhost:5000` (or your server's IP/hostname).

## Usage

- **Register:** Create a new user account.
- **Login:** Log in using password and 2FA.
- **Upload Files:** Upload files securely; files are encrypted before storage.
- **Share Files:** Share files with other users, define permissions and expiry.
- **Download/Delete:** Download or delete your files as needed.
- **View Logs:** Check your activity logs; admins can see all logs.
- **Admin Panel:** Admins can manage users, files, and system logs.

## Security Highlights

- All sensitive data is encrypted at rest and during transmission.
- 2FA and RBAC reduce risk of unauthorized access.
- Blockchain logging ensures all activity is tamper-proof and auditable.
- Real-time alerts keep users informed of account activity.

## Future Enhancements

- Hybrid cloud storage integration with external providers.
- Advanced analytics for admin panel.
- Additional authentication options (e.g. biometric, hardware tokens).


## Author

- [Akash Sarkar](https://github.com/akash-sarkar-2001)
