package uk.co.kennah.encrypt;

import uk.co.kennah.encrypt.utils.KeGen;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class KeGenTest {

    private KeGen keyPair;
    private final int BITS = 1024; // Use a smaller key size for faster tests

    @BeforeEach
    void setUp() {
        // Generate a new key pair before each test
        keyPair = new KeGen(BITS);
    }

    @Test
    @DisplayName("Should generate non-null key components")
    void testKeyComponentsAreNotNull() {
        assertNotNull(keyPair.getPublicKey(), "Public key should not be null.");
        assertNotNull(keyPair.getPrivateKey(), "Private key should not be null.");
        assertNotNull(keyPair.getModulus(), "Modulus should not be null.");
    }

    @Test
    @DisplayName("Public exponent 'e' should be the standard value 65537")
    void testPublicExponentIsStandard() {
        // Using 65537 as the public exponent is a common practice for efficiency.
        BigInteger expectedPublicExponent = new BigInteger("65537");
        assertEquals(expectedPublicExponent, keyPair.getPublicKey(), "Public exponent 'e' should be 65537.");
    }

    // Repetition is good for tests involving randomness to ensure consistency.
    @RepeatedTest(5)
    @DisplayName("Modulus 'n' should have the correct bit length")
    void testModulusBitLength() {
        int bitLength = keyPair.getModulus().bitLength();
        // The bit length of n = p*q will be either BITS or BITS-1
        assertTrue(bitLength == BITS || bitLength == BITS - 1,
                "Modulus bit length (" + bitLength + ") should be " + BITS + " or " + (BITS - 1));
    }

    // This is the most critical test. Repeating it ensures the key math is consistently correct.
    @RepeatedTest(5)
    @DisplayName("Keys should correctly encrypt and decrypt (round-trip test)")
    void testRoundTripEncryptionDecryption() {
        // This test verifies the mathematical relationship between the keys.
        // It uses textbook RSA (modPow) which is suitable for testing the keys themselves.
        BigInteger message = new BigInteger("This is a test message for the repeated KeGen class test".getBytes());

        // Encrypt with public key: ciphertext = message^e mod n
        BigInteger ciphertext = message.modPow(keyPair.getPublicKey(), keyPair.getModulus());

        // Decrypt with private key: decrypted_message = ciphertext^d mod n
        BigInteger decryptedMessage = ciphertext.modPow(keyPair.getPrivateKey(), keyPair.getModulus());

        assertEquals(message, decryptedMessage, "Decrypted message should match the original message.");
    }

    @Test
    @DisplayName("Should generate different keys on subsequent calls")
    void testKeyGenerationIsRandom() {
        KeGen anotherKeyPair = new KeGen(BITS);
        assertNotEquals(keyPair.getModulus(), anotherKeyPair.getModulus(), "Modulus of two different key pairs should not be the same.");
        assertNotEquals(keyPair.getPrivateKey(), anotherKeyPair.getPrivateKey(), "Private key of two different key pairs should not be the same.");
    }
}
