package uk.co.kennah.encrypt.utils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * A class to perform RSA encryption and decryption with PKCS#1 v1.5 padding.
 * This is for educational purposes to demonstrate how padding works.
 */
public class PaddedRSA {

    /**
     * Encrypts a message using the public key components.
     * @param message The message to encrypt.
     * @param e The public exponent.
     * @param n The modulus.
     * @return The encrypted ciphertext as a BigInteger.
     */
    public static BigInteger encrypt(byte[] message, BigInteger e, BigInteger n) {
        int keyByteLength = (n.bitLength() + 7) / 8;

        // 1. Pad the message
        byte[] paddedMessage = pad(message, keyByteLength);

        // 2. Convert the padded byte array to a BigInteger
        BigInteger m = new BigInteger(1, paddedMessage);

        // 3. Perform the RSA encryption: c = m^e mod n
        return m.modPow(e, n);
    }

    /**
     * Decrypts a ciphertext using the private key components.
     * @param ciphertext The ciphertext to decrypt.
     * @param d The private exponent.
     * @param n The modulus.
     * @return The original message as a byte array.
     */
    public static byte[] decrypt(BigInteger ciphertext, BigInteger d, BigInteger n) {
        // 1. Perform RSA decryption: m = c^d mod n
        BigInteger m = ciphertext.modPow(d, n);

        // 2. Convert the result to a byte array
        byte[] decryptedBytes = m.toByteArray();
        
        // 3. The decrypted byte array must be the same length as the key.
		//    If it's shorter, it's because leading zeros were truncated.
		//    If it's longer, it's because toByteArray() added a sign bit.
		//    We need to restore it to the exact key length before unpadding.
		int keyByteLength = (n.bitLength() + 7) / 8;
		byte[] paddedMessage = new byte[keyByteLength];

		if (decryptedBytes.length > keyByteLength) {
			// toByteArray() added a leading 0x00 for the sign bit, ignore it.
			System.arraycopy(decryptedBytes, 1, paddedMessage, 0, keyByteLength);
		} else {
			// Copy the bytes to the right end of the array, effectively left-padding with zeros.
			System.arraycopy(decryptedBytes, 0, paddedMessage, keyByteLength - decryptedBytes.length, decryptedBytes.length);
		}

		// 4. Unpad the message
		return unpad(paddedMessage);
    }

    /**
     * Implements PKCS#1 v1.5 padding.
     * Format: 0x00 || 0x02 || PS || 0x00 || M
     */
    private static byte[] pad(byte[] message, int keyByteLength) {
        if (message.length > keyByteLength - 11) {
            throw new IllegalArgumentException("Message too long for RSA padding");
        }
        int psLength = keyByteLength - message.length - 3;
        byte[] ps = new byte[psLength];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ps);
        // Ensure no zero bytes in the padding string
        for (int i = 0; i < ps.length; i++) {
            while (ps[i] == 0) {
                ps[i] = (byte) random.nextInt();
            }
        }

        byte[] padded = new byte[keyByteLength];
        padded[0] = 0x00;
        padded[1] = 0x02;
        System.arraycopy(ps, 0, padded, 2, ps.length);
        padded[2 + ps.length] = 0x00;
        System.arraycopy(message, 0, padded, 3 + ps.length, message.length);
        return padded;
    }

    /**
     * Removes PKCS#1 v1.5 padding.
     */
    private static byte[] unpad(byte[] padded) {
        // Find the 0x00 separator byte
        int separatorIndex = -1;
        for (int i = 2; i < padded.length; i++) {
            if (padded[i] == 0) {
                separatorIndex = i;
                break;
            }
        }
        if (separatorIndex == -1) {
            throw new RuntimeException("Invalid padding: separator not found");
        }
        // The message is everything after the separator
        return Arrays.copyOfRange(padded, separatorIndex + 1, padded.length);
    }
}
