package uk.co.kennah.encrypt.utils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author Tony Kennah
 */
public class KeGen {
	
	private final BigInteger privateKey;
	private final BigInteger publicKey;
	private final BigInteger modulus;

	/**
	 * Generates an RSA key pair with the specified bit length.
	 * This is for educational purposes. For production, always use
	 * java.security.KeyPairGenerator.
	 *
	 * @param bitLength The desired bit length of the key (e.g., 2048).
	 */
	public KeGen(int bitLength) {
		SecureRandom rand = new SecureRandom();
		// 1. Find two large, distinct prime numbers, p and q.
		// We use BigInteger.probablePrime for this, which is a standard and secure way.
		// A true from-scratch implementation would need its own Miller-Rabin primality test.
		BigInteger p = BigInteger.probablePrime(bitLength / 2, rand);
		BigInteger q = BigInteger.probablePrime(bitLength / 2, rand);

		// 2. Compute n = p * q. This is the modulus for both keys.
		this.modulus = p.multiply(q);

		// 3. Compute Euler's totient function: phi(n) = (p-1) * (q-1).
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

		// 4. Choose the public exponent 'e'. 65537 is a common and secure choice.
		this.publicKey = new BigInteger("65537"); // e

		// 5. Compute the private exponent 'd', the modular multiplicative inverse of e (mod phi).
		this.privateKey = publicKey.modInverse(phi); // d
	}
	
	public BigInteger getModulus() {
		return modulus;
	}
	
	public BigInteger getPublicKey() {
		return publicKey;
	}
	
	public BigInteger getPrivateKey() {
		return privateKey;
	}
}	