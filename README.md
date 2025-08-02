# SecureProperties

A simple encrypted properties implementation using Jasypt. This utility allows for storing both plain-text and encrypted values in a single properties file. The password for the symmetric encryption is itself asymmetrically encrypted and stored within the same file, providing a self-contained secret management solution.

## How It Works

1.  **Symmetric Encryption:** Property values are encrypted using a strong symmetric encryption algorithm (provided by Jasypt). This requires a password.
2.  **Asymmetric Encryption:** To avoid storing the symmetric password in plain text, it is encrypted using an asymmetric algorithm (e.g., RSA).
3.  **Key Storage:** The encrypted symmetric password is then stored in the properties file itself under the `TK.ACCESS.AUTHENTICATION.TOKENS` key.

When the application starts, it uses a private key to decrypt the `TK.ACCESS.AUTHENTICATION.TOKENS` value, retrieve the symmetric password, and initialize the Jasypt encryptor to read the other encrypted properties.

## Security Considerations

The security of this entire system depends on the **secrecy of the private key** used for the asymmetric decryption. This private key must be stored securely and should not be checked into version control. It should be provided to the application via a secure mechanism, such as environment variables, a secure vault (like HashiCorp Vault), or other secrets management tools.

## Usage

```java
public static void main(String[] args) {
    // Assumes the private key is available to the application
    SecureProperties sp = SecureProperties.getInstance("file.txt");

    // Set properties
    sp.setProperty("not.encrypted", "Readable value");
    sp.setEncryptedProperty("is.encrypted", "This will be unreadable in the file");

    // Save to the file
    sp.store();

    // Reading properties
    System.out.println(sp.getProperty("is.encrypted")); // Prints the decrypted value
}
