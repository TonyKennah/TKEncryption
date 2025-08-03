package uk.co.kennah.encrypt;

import uk.co.kennah.encrypt.utils.KeGen;
import uk.co.kennah.encrypt.utils.PaddedRSA;

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

        // The public key is a small, fixed number, so we can print it fully.
        System.out.println("Public Key (e):  " + keyPair.getPublicKey());
        // The private key and modulus are very large, so we'll print the first 60 characters.
        System.out.println("Private Key (d): " + privateKeyStr.substring(0, Math.min(privateKeyStr.length(), 60)) + "...");
        System.out.println("Modulus (n):     " + modulusStr.substring(0, Math.min(modulusStr.length(), 60)) + "...");


		// The message to be encrypted.
		String originalMessage = "This is a secret message for the RSA demo!";
		byte[] originalBytes = originalMessage.getBytes(StandardCharsets.UTF_8);

		// 2. Encrypt the message using the PUBLIC key (e, n).
		// Anyone can have the public key to encrypt data for the key owner.
		System.out.println("\nEncrypting with PUBLIC key...");
		BigInteger ciphertext = PaddedRSA.encrypt(originalBytes, keyPair.getPublicKey(), keyPair.getModulus());
		String ciphertextStr = ciphertext.toString();
		System.out.println("Ciphertext: " + ciphertextStr.substring(0, Math.min(ciphertextStr.length(), 60)) + "...");

		// 3. Decrypt the message using the PRIVATE key (d, n).
		// Only the owner of the private key can decrypt the data.
		System.out.println("\nDecrypting with PRIVATE key...");
		byte[] decryptedBytes = PaddedRSA.decrypt(ciphertext, keyPair.getPrivateKey(), keyPair.getModulus());
		String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

		System.out.println("\n--- Results ---");
		System.out.println("Original Message:  " + originalMessage);
		System.out.println("Decrypted Message: " + decryptedMessage);

	}

}
