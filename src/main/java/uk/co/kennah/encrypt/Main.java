package uk.co.kennah.encrypt;

import uk.co.kennah.encrypt.utils.KeGen;
import uk.co.kennah.encrypt.utils.PaddedRSA;

import java.io.Console;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class Main {

	public static void main(String[] args) {

        System.out.println("--- RSA Encryption Demo (Educational) ---");

        // 1. Generate a strong 2048-bit key pair.
        // In a real application, this is done once and the keys are stored securely.
        System.out.println("Generating 2048-bit RSA key pair...");
        KeGen keyPair = new KeGen(2048);
        System.out.println("Key pair generated.");

        System.out.println("\n--- Generated Keys (truncated for display) ---");
        String privateKeyStr = keyPair.getPrivateKey().toString();
        String modulusStr = keyPair.getModulus().toString();
        String truncatedModulus = modulusStr.substring(0, Math.min(modulusStr.length(), 60)) + "...";

        System.out.println("Public Key (e, n):");
        System.out.println("  e: " + keyPair.getPublicKey());
        System.out.println("  n: " + truncatedModulus);

        System.out.println("\nPrivate Key (d, n):");
        System.out.println("  d: " + privateKeyStr.substring(0, Math.min(privateKeyStr.length(), 60)) + "...");
        System.out.println("  n: " + truncatedModulus);

        // Get the message to be encrypted from user input.
        Console console = System.console();
        if (console == null) {
            // This can happen when running inside certain IDEs.
            // Running from a command line terminal is recommended.
            System.err.println("\nNo console available. Please run from a terminal.");
            System.exit(1);
        }

        System.out.print("\nEnter the message to encrypt: ");
        String originalMessage = console.readLine();
        byte[] originalBytes = originalMessage.getBytes(StandardCharsets.UTF_8);

        // 2. Encrypt the message using the PUBLIC key (e, n).
        // Anyone can have the public key to encrypt data for the key owner.
        System.out.println("\nEncrypting with PUBLIC key...");
        BigInteger ciphertext = PaddedRSA.encrypt(originalBytes, keyPair.getPublicKey(), keyPair.getModulus());
        String ciphertextStr = ciphertext.toString();
        System.out.println("Ciphertext (as a large integer): " + ciphertextStr.substring(0, Math.min(ciphertextStr.length(), 60)) + "...");
        System.out.println("  - This number is the result of the RSA formula: (padded_message ^ e) mod n.");
        System.out.println("  - It appears random and its value is guaranteed to be less than the modulus (n).");
        System.out.println("  - Because of the random padding, encrypting the same message again would produce a different ciphertext.");
        System.out.println("  - Bit length of ciphertext: " + ciphertext.bitLength() + " (will be close to the key bit length of 2048)");

        // 3. Decrypt the message using the PRIVATE key (d, n).
        // Only the owner of the private key can decrypt the data.
        System.out.println("\nDecrypting with PRIVATE key...");
        byte[] decryptedBytes = PaddedRSA.decrypt(ciphertext, keyPair.getPrivateKey(), keyPair.getModulus());
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        System.out.println("\n--- Results ---");
        System.out.println("Original Message:  " + originalMessage);
        System.out.println("Decrypted Message: " + decryptedMessage + "\n");

	}

}
