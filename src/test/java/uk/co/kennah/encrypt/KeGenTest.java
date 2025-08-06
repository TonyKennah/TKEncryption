package uk.co.kennah.encrypt;

import uk.co.kennah.encrypt.utils.KeGen;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

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
        BigInteger message = new BigInteger("This is a test message for the repeated KeGen class test".getBytes(StandardCharsets.UTF_8));

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

    @Test
    @DisplayName("Should handle p and q being the same initial prime and regenerate")
    void testHandlesIdenticalPrimes() {
        // Two distinct, known prime numbers for predictable testing.
        final BigInteger prime1 = new BigInteger("587");
        final BigInteger prime2 = new BigInteger("593");

        // A queue to control the sequence of primes returned by our mock generator.
        // It will return prime1, then prime1 again (the duplicate case), then prime2.
        final java.util.Queue<BigInteger> primeSequence = new java.util.LinkedList<>();
        primeSequence.add(prime1); // First prime (p)
        primeSequence.add(prime1); // Second prime (q), the duplicate that should be rejected
        primeSequence.add(prime2); // Third prime (q), the valid second prime

        // Create an anonymous subclass of KeGen to override the prime generation.
        // This is a form of dependency injection for testing purposes.
        KeGen keyGenWithControlledPrimes = new KeGen(BITS) {
            @Override
            protected BigInteger generatePrime(int bitLength, SecureRandom random) {
                // Instead of generating a random prime, we pull from our predefined sequence.
                return primeSequence.poll();
            }
        };

        // We can explicitly check that the final modulus is the product of the two *distinct* primes.
        BigInteger expectedModulus = prime1.multiply(prime2);
        assertEquals(expectedModulus, keyGenWithControlledPrimes.getModulus(), "Modulus should be the product of the two distinct primes.");
    }
}
