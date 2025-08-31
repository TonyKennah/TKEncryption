[![Build & Test Status](https://github.com/TonyKennah/TKEncryption/actions/workflows/maven.yml/badge.svg)](https://github.com/TonyKennah/TKEncryption/actions/workflows/maven.yml)

# TKEncryption

An educational Java project demonstrating hybrid encryption by implementing parts of the cryptographic stack from scratch.

## Overview

This project was created to explore the inner workings of common cryptographic algorithms. It started with a basic RSA implementation and evolved into a hybrid system that combines the strengths of both asymmetric (RSA) and symmetric (AES) cryptography. This allows it to encrypt messages of any length, overcoming the size limitations of using RSA alone.

### The "Safe and Strongbox" Analogy

Hybrid encryption can be understood with a simple analogy, which is also reflected in the console output of this program:

1.  **The Strongbox (AES):** Your large message is placed inside a "strongbox" and locked with a simple, fast key. This represents symmetric encryption (AES), which is very efficient for large amounts of data.

2.  **The Safe (RSA):** The small key for the strongbox is then placed inside a nearly unbreakable "safe". This safe can only be opened with a unique private key that only the recipient has. This represents asymmetric encryption (RSA), which is perfect for securely transferring the small AES key.

3.  **The Package:** The locked strongbox and the locked safe are sent together. The recipient uses their private key to open the safe, retrieves the strongbox key, and then uses that key to open the strongbox and read the message.

This approach gives you the best of both worlds: the convenience of public-key cryptography and the performance of symmetric-key cryptography.

## Features

- **Hybrid Encryption:** Combines a custom RSA implementation for key exchange with the standard Java `Cipher` for AES data encryption.
- **Custom RSA Key Generation:** `KeGenRSA.java` provides from-scratch logic for generating RSA public/private key pairs.
- **Custom AES Key Generation:** `KeGenAES.java` provides a simple utility to generate a cryptographically secure random key for AES, replacing `javax.crypto.KeyGenerator`.
- **Custom RSA Padding:** `PaddedRSA.java` implements RSA encryption and decryption with PKCS#1 v1.5 padding.

---

### ⚠️ Security Disclaimer

**IMPORTANT:** This project is for **educational purposes only**.

The custom cryptographic implementations are simplified to be understandable and are **not secure for production use**. They have not been hardened against side-channel attacks or other advanced vulnerabilities. For any real-world application, always use standard, well-vetted cryptographic libraries like Java's `javax.crypto` package.

---


## Building the Project
To compile the source code, run the following Maven command from the project's root directory:

```bash
   mvn compile
```

This will download dependencies and compile the Java classes into the target/classes directory.

Running the Tests
The project includes a suite of JUnit 5 tests to verify the correctness of the key generation logic. To run these tests, use:

```bash
   mvn test
```

A report of the test results will be generated in the target/surefire-reports directory.

Running the Application
To run the interactive encryption demo, execute the following command:


```bash
   mvn exec:java
```

The application will:

Generate a new 2048-bit RSA key pair.
Prompt you to enter a message to encrypt.
Display the encrypted and then decrypted message to demonstrate a successful round-trip.


## Project Structure

-   `Main.java`: The entry point for the application. Demonstrates the full encryption and decryption flow.
-   `HybridEncryptor.java`: The core class that orchestrates the hybrid encryption scheme. It generates a one-time AES key, encrypts the data with it, and then encrypts the AES key using RSA.

### Utility Classes (`utils/`)

-   `KeGenRSA.java`: Generates RSA public and private key pairs of a specified bit length.
-   `KeGenAES.java`: A simple utility to generate a cryptographically secure random key for AES.
-   `PaddedRSA.java`: Implements RSA encryption and decryption with PKCS#1 v1.5 padding.

# Future

Switch to AES-GCM
