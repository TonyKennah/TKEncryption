package uk.co.kennah.encrypt;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import uk.co.kennah.encrypt.utils.KeGenAES;
import uk.co.kennah.encrypt.utils.KeGenRSA;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class HybridEncryptorTest {

    private static KeGenRSA rsaKeyPair;
    private static SecretKey aesKey;

    @BeforeAll
    static void setUp() {
        // Generate keys once for all tests to save time, as RSA key gen is slow.
        rsaKeyPair = new KeGenRSA(2048);
        aesKey = KeGenAES.generateKey(128);
    }

    @Test
    @DisplayName("Should encrypt and decrypt a message successfully")
    void testEncryptAndDecrypt_SuccessfulRoundTrip() throws Exception {
        // Arrange
        String originalMessage = "This is a test message for the hybrid encryption round-trip!";
        byte[] originalMessageBytes = originalMessage.getBytes(StandardCharsets.UTF_8);
        BigInteger publicKey = rsaKeyPair.getPublicKey();
        BigInteger privateKey = rsaKeyPair.getPrivateKey();
        BigInteger modulus = rsaKeyPair.getModulus();

        // Act
        byte[] ciphertext = HybridEncryptor.encrypt(originalMessageBytes, aesKey, publicKey, modulus);
        byte[] decryptedBytes = HybridEncryptor.decrypt(ciphertext, privateKey, modulus);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        // Assert
        assertAll(
                () -> assertNotNull(ciphertext, "Ciphertext should not be null"),
                () -> assertNotEquals(0, ciphertext.length, "Ciphertext should not be empty"),
                () -> assertNotEquals(originalMessage, new String(ciphertext, StandardCharsets.UTF_8), "Ciphertext should be different from original message"),
                () -> assertEquals(originalMessage, decryptedMessage, "Decrypted message should match the original")
        );
    }

    @Test
    @DisplayName("Should handle an empty message")
    void testEncryptAndDecrypt_EmptyMessage() throws Exception {
        // Arrange
        String originalMessage = "";
        byte[] originalMessageBytes = originalMessage.getBytes(StandardCharsets.UTF_8);

        // Act
        byte[] ciphertext = HybridEncryptor.encrypt(originalMessageBytes, aesKey, rsaKeyPair.getPublicKey(), rsaKeyPair.getModulus());
        byte[] decryptedBytes = HybridEncryptor.decrypt(ciphertext, rsaKeyPair.getPrivateKey(), rsaKeyPair.getModulus());
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        // Assert
        assertEquals("", decryptedMessage, "Decrypting an empty message should result in an empty string");
    }

    @Test
    @DisplayName("Should fail to decrypt with the wrong private key")
    void testDecrypt_WithWrongKey_ShouldFail() throws Exception {
        // Arrange
        String originalMessage = "This message should not be recoverable.";
        byte[] originalMessageBytes = originalMessage.getBytes(StandardCharsets.UTF_8);
        KeGenRSA wrongKeyPair = new KeGenRSA(2048); // A different key pair

        byte[] ciphertext = HybridEncryptor.encrypt(originalMessageBytes, aesKey, rsaKeyPair.getPublicKey(), rsaKeyPair.getModulus());

        // Act & Assert: Decrypting with the wrong key should throw an exception.
        // The exception can vary (e.g., InvalidKeyException from a bad AES key length,
        // or a padding error from PaddedRSA.unpad) because decrypting the AES key
        // with the wrong RSA key produces garbage. The core assertion is that the
        // decryption process must fail, not produce incorrect data.
        assertThrows(Exception.class, () -> HybridEncryptor.decrypt(ciphertext, wrongKeyPair.getPrivateKey(), wrongKeyPair.getModulus()),
                "Decryption with the wrong key should throw an exception.");
    }
}