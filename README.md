# Secure CLI Password Manager

## Scope
This project is a command-line interface (CLI) secure password manager developed for the ICS0022 Secure Programming course. 
It focuses on the secure local storage of credentials, strict memory management to prevent data leaks, and robust input validation to protect against buffer overflows and injection attacks.

## Tech Stack
* **Language:** C
* **Database:** SQLite (local file)
* **Cryptography:** OpenSSL (or Libsodium)

## Features & Planned Screens
**Key Features:**
* Secure master password authentication.
* Local symmetric encryption for all stored vault credentials (stored as BLOBs).
* Secure memory management (sensitive data is wiped from RAM immediately after use)[cite: 8].
* Defenses against SQL injection and memory corruption (using safe string functions)[cite: 8].

**Planned Interactive Screens:**
* `Login / Setup` - Master password prompt and vault initialization.
* `Main Menu` - The core interactive loop.
* `Add Entry` - Prompt to securely input and encrypt a new credential.
* `Retrieve Entry` - Decrypt and display a password temporarily.
* `Exit` - Lock the vault and securely terminate the process.

## How to Build and Run Locally
The application is designed to run locally and can be compiled using a standard C compiler.

1. Clone this repository.
2. Navigate to the project root directory in your terminal.
3. Compile the project :
   ```bash
   make
   ```
4. Run the executable:
```
./pass
```