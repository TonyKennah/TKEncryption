package uk.co.kennah.encrypt.utils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * A utility to generate AES keys without relying on KeyGenerator.
 * This is for educational purposes to show that an AES key is just a set of random bytes.
 */
public class KeGenAES {

    private static final String ALGORITHM = "AES";

    /**
     * Generates a new AES secret key with the specified bit length.
     *
     * @param keySizeInBits The desired key size in bits (e.g., 128, 192, 256).
     * @return A new SecretKey for AES.
     */
    public static SecretKey generateKey(int keySizeInBits) {
        if (keySizeInBits != 128 && keySizeInBits != 192 && keySizeInBits != 256) {
            throw new IllegalArgumentException("Invalid AES key size: " + keySizeInBits + ". Must be 128, 192, or 256.");
        }
        int keySizeInBytes = keySizeInBits / 8;
        byte[] keyBytes = new byte[keySizeInBytes];
        new SecureRandom().nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }
}
