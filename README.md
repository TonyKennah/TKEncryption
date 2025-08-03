# RSA Encryption Demo

[![Java CI with Maven](https://github.com/tonykennah/tk-encrypt/actions/workflows/maven.yml/badge.svg)](https://github.com/tonykennah/tk-encrypt/actions/workflows/maven.yml)

This project is a simple, educational command-line application demonstrating the principles of RSA encryption and decryption using pure Java and `BigInteger`. It includes key generation, OAEP-style padding, and a round-trip demonstration of encrypting and decrypting a user-provided message.

> [!WARNING]
> **For Educational Use Only**
>
> This implementation is for educational purposes to demonstrate the mechanics of RSA. It has not been subjected to a formal security audit and may contain vulnerabilities. **Do not use this code in a production environment.**
> For production-grade cryptography, always use well-vetted, standard libraries like Java's `javax.crypto` or Bouncy Castle.

## Prerequisites

*   Java Development Kit (JDK) 17 or later
*   Apache Maven

## Building the Project

To compile the source code, run the following Maven command from the project's root directory:

```sh
mvn compile
```

This will download dependencies and compile the Java classes into the `target/classes` directory.

## Running the Tests

The project includes a suite of JUnit 5 tests to verify the correctness of the key generation logic. To run these tests, use:

```sh
mvn test
```

A report of the test results will be generated in the `target/surefire-reports` directory.

## Running the Application

To run the interactive encryption demo, execute the following command:

```sh
mvn exec:java
```

The application will:
1.  Generate a new 2048-bit RSA key pair.
2.  Prompt you to enter a message to encrypt.
3.  Display the encrypted and then decrypted message to demonstrate a successful round-trip.