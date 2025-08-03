# From-Scratch RSA Encryption Demo

[![Build Status](https://github.com/TonyKennah/SecureProperties/actions/workflows/maven.yml/badge.svg)](https://github.com/TonyKennah/SecureProperties/actions/workflows/maven.yml)

This project is an educational tool designed to demonstrate the inner workings of RSA asymmetric encryption by implementing its core components from the ground up in Java.

**The primary goal is learning, not production use.**

## Objective

The purpose of this project is to demystify asymmetric encryption. Instead of relying on the standard Java Cryptography Architecture (JCA) as a "black box," this code builds the key generation and encryption/decryption logic manually to provide a clear view of the underlying mathematics and security concepts, such as padding.

## Core Components

-   `src/main/java/uk/co/kennah/encrypt/utils/KeGen.java`
    -   A custom key generator that creates a 2048-bit RSA key pair. It finds two large prime numbers and calculates the public exponent (`e`), private exponent (`d`), and the shared modulus (`n`).

-   `src/main/java/uk/co/kennah/encrypt/utils/PaddedRSA.java`
    -   An implementation of the RSA algorithm that includes **PKCS#1 v1.5 padding**. This is a critical component that adds randomness to the message before encryption to prevent common cryptographic attacks, moving beyond an insecure "textbook" implementation.

-   `src/main/java/uk/co/kennah/encrypt/Main.java`
    -   The main driver class that showcases the entire process.

## Continuous Integration

This project uses GitHub Actions to automatically build the code on every push to the `master` branch. This ensures that the project remains compilable and healthy. The build status badge at the top of this README reflects the result of the latest build.

## How to Run the Demo

You can run the demonstration using Maven from the project's root directory:

```bash
mvn compile exec:java -Dexec.mainClass="uk.co.kennah.encrypt.Main"
```

### Expected Output

When you run the application, it will:
1.  Generate a new 2048-bit RSA key pair.
2.  Display the public and private key components (the exponents `e` and `d`, and the shared modulus `n`).
3.  Take a sample message and encrypt it using the public key.
4.  Display the resulting ciphertext, explaining what it represents and why it's secure.
5.  Decrypt the ciphertext using the private key.
6.  Show that the decrypted message perfectly matches the original, proving the process was successful.

---

## ⚠️ Critical Security Warning ⚠️

This project is for **educational purposes only**.

**DO NOT use this code in any production environment.**

Implementing cryptography from scratch is extremely difficult and prone to subtle, hard-to-detect vulnerabilities. Real-world security relies on standard, peer-reviewed, and battle-tested libraries like Java's `java.security` and `javax.crypto` packages. These libraries are maintained by security experts and provide guarantees that a from-scratch implementation cannot.