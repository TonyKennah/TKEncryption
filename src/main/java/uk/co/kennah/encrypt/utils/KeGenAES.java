package uk.co.kennah.encrypt.utils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Utility class for generating AES keys.
 */
public class KeGenAES {

    private static final String AES_ALGORITHM = "AES";

    /**
     * Generates a new AES secret key of the specified key size.
     *
     * @param keySize The key size in bits (e.g., 128, 192, 256).
     * @return A new AES SecretKey.
     * @throws NoSuchAlgorithmException If the AES algorithm is not available.
     */
    public static SecretKey generateKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(keySize, new SecureRandom()); // Use SecureRandom for strong key generation
        return keyGen.generateKey();
    }
}
