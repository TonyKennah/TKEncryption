package uk.co.kennah.encrypt;

import uk.co.kennah.encrypt.utils.PaddedRSA;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Implements a hybrid encryption scheme using RSA and AES.
 * RSA is used to encrypt a symmetric AES key, and AES is used to encrypt the data.
 */
public class HybridEncryptor {

    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int AES_KEY_SIZE = 128; // bits
    private static final int IV_SIZE = 16; // bytes

    /**
     * Encrypts a message of any size using a hybrid RSA-AES scheme.
     *
     * @param message The plaintext message to encrypt.
     * @param aesKey  The one-time AES key to use for this encryption.
     * @param e       The public RSA exponent.
     * @param n       The public RSA modulus.
     * @return A single byte array containing the encrypted AES key, IV, and encrypted message.
     * @throws Exception if encryption fails.
     */
    public static byte[] encrypt(byte[] message, SecretKey aesKey, BigInteger e, BigInteger n) throws Exception {
        // 1. The one-time AES key is now passed in as a parameter.

        // 2. Generate a random Initialization Vector (IV) for this encryption operation.
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 3. Encrypt the actual message with AES.
        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encryptedMessage = aesCipher.doFinal(message);

        System.out.println("Message put in Strongbox ");

        // 4. Encrypt the small AES key with RSA.
        BigInteger encryptedAesKeyBI = PaddedRSA.encrypt(aesKey.getEncoded(), e, n);
        System.out.println("Strongbox key placed in Safe and Safe Locked with public key.");

        // 5. Convert the encrypted key BigInteger to a fixed-size byte array.
        int keyByteLength = (n.bitLength() + 7) / 8;
        byte[] encryptedAesKeyBytes = toFixedSizeBytes(encryptedAesKeyBI, keyByteLength);

        // 6. Combine everything into a single payload: [Encrypted AES Key][IV][Encrypted Message]
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(encryptedAesKeyBytes);
        outputStream.write(iv);
        outputStream.write(encryptedMessage);

        System.out.println("Safe and Strongbox packaged together and sent to the recipient\n---");

        return outputStream.toByteArray();
    }

    /**
     * Decrypts a hybrid-encrypted message.
     *
     * @param hybridCiphertext The combined encrypted payload.
     * @param d                The private RSA exponent.
     * @param n                The private RSA modulus.
     * @return The original plaintext message.
     * @throws Exception if decryption fails.
     */
    public static byte[] decrypt(byte[] hybridCiphertext, BigInteger d, BigInteger n) throws Exception {
        int keyByteLength = (n.bitLength() + 7) / 8;

        // 1. Unpack the payload: [Encrypted AES Key][IV][Encrypted Message]
        byte[] encryptedAesKeyBytes = new byte[keyByteLength];
        System.arraycopy(hybridCiphertext, 0, encryptedAesKeyBytes, 0, keyByteLength);

        System.out.println("---\nSafe and Strongbox received.");
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(hybridCiphertext, keyByteLength, iv, 0, IV_SIZE);

        byte[] encryptedMessage = new byte[hybridCiphertext.length - keyByteLength - IV_SIZE];
        System.arraycopy(hybridCiphertext, keyByteLength + IV_SIZE, encryptedMessage, 0, encryptedMessage.length);

        // 2. Decrypt the AES key with RSA.
        BigInteger encryptedAesKeyBI = new BigInteger(1, encryptedAesKeyBytes);
        byte[] decryptedAesKeyBytes = PaddedRSA.decrypt(encryptedAesKeyBI, d, n);

        // 3. Reconstruct the AES key and IV.
        SecretKey aesKey = new SecretKeySpec(decryptedAesKeyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        System.out.println("Safe opened with private key, Strongbox key retrieved.");

        // 4. Decrypt the message with AES.
        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        System.out.println("Strongbox opened, message retrieved.");
        return aesCipher.doFinal(encryptedMessage);
    }

    /**
     * Converts a BigInteger to a byte array of a fixed size, padding with leading zeros
     * or trimming the sign bit as necessary.
     */
    private static byte[] toFixedSizeBytes(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        byte[] fixedSizeBytes = new byte[length];

        if (bytes.length > length) {
            // toByteArray() may add a leading 0x00 for the sign bit, ignore it.
            System.arraycopy(bytes, bytes.length - length, fixedSizeBytes, 0, length);
        } else {
            // Copy the bytes to the right end of the array, effectively left-padding with zeros.
            System.arraycopy(bytes, 0, fixedSizeBytes, length - bytes.length, bytes.length);
        }
        return fixedSizeBytes;
    }
}