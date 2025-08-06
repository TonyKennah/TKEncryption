package uk.co.kennah.encrypt;

import uk.co.kennah.encrypt.utils.KeGenAES;
import uk.co.kennah.encrypt.utils.KeGenRSA;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import java.util.Scanner;
import java.util.Base64;


public class Main {

    public static void main(String[] args) {
        try {
            KeGenRSA keyPair = new KeGenRSA(2048);
            BigInteger publicKey = keyPair.getPublicKey();
            BigInteger privateKey = keyPair.getPrivateKey();
            BigInteger modulus = keyPair.getModulus();

            System.out.println("Generating RSA Key pair (Expensive but small Safe) ---");
            String privateKeyStr = keyPair.getPrivateKey().toString();
            String modulusStr = keyPair.getModulus().toString();
            String truncatedModulus = modulusStr.substring(0, Math.min(modulusStr.length(), 60)) + "...";

            System.out.println("\nPublic Key (e, n):");
            System.out.println("  e: " + keyPair.getPublicKey());
            System.out.println("  n: " + truncatedModulus);

            System.out.println("\nPrivate Key (d, n):");
            System.out.println("  d: " + privateKeyStr.substring(0, Math.min(privateKeyStr.length(), 60)) + "...");
            System.out.println("  n: " + truncatedModulus);

            // For each message, generate a new, one-time-use AES key.
            System.out.println("\n\nGenerating one-time AES key (Inexpensive but large Strongbox) for this message...");
            SecretKey aesKey = KeGenAES.generateKey(128);
            StringBuilder hexKey = new StringBuilder();
            for (byte b : aesKey.getEncoded()) {
                hexKey.append(String.format("%02x", b));
            }
            System.out.println("\nAES Key (128-bit):");
            System.out.println("  " + hexKey.toString());


            String originalMessage;
            System.out.print("\nEnter the message to encrypt: ");
            if (System.console() != null) {
                // Preferred method for reading from a terminal
                originalMessage = System.console().readLine();
            } else {
                // Fallback for IDEs where System.console() is null
                Scanner scanner = new Scanner(System.in);
                originalMessage = scanner.nextLine();
            }

            System.out.println("Original Message (length " + originalMessage.length() + "): " + originalMessage);

            // Encrypt using the hybrid scheme
            System.out.println("\nEncrypting with hybrid (RSA+AES) scheme...");
            byte[] hybridCiphertext = HybridEncryptor.encrypt(originalMessage.getBytes(StandardCharsets.UTF_8), aesKey,
                    publicKey, modulus);
            System.out.println("Encryption successful!");
            System.out.println("\n\nHybrid Ciphertext (Base64): " + Base64.getEncoder().encodeToString(hybridCiphertext));

            // Decrypt using the hybrid scheme
            System.out.println("\nDecrypting with hybrid scheme...");
            byte[] decryptedBytes = HybridEncryptor.decrypt(hybridCiphertext, privateKey, modulus);
            String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
            System.out.println("Decryption successful!");
            System.out.println("\nDecrypted Message: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}