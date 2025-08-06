package uk.co.kennah.encrypt.utils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author Tony Kennah
 */
public class KeGenRSA {
	
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
	public KeGenRSA(int bitLength) {
		SecureRandom rand = new SecureRandom();
		// 1. Find two large, distinct prime numbers, p and q.
		BigInteger p = generatePrime(bitLength / 2, rand);
		BigInteger q;
		do {
			q = generatePrime(bitLength / 2, rand);
		} while (p.equals(q)); // Ensure p and q are distinct primes.

		// 2. Compute n = p * q. This is the modulus for both keys.
		this.modulus = p.multiply(q);

		// 3. Compute Euler's totient function: phi(n) = (p-1) * (q-1).
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

		// 4. Choose the public exponent 'e'. 65537 is a common and secure choice.
		this.publicKey = new BigInteger("65537"); // e

		// 5. Compute the private exponent 'd', the modular multiplicative inverse of e (mod phi).
		this.privateKey = publicKey.modInverse(phi); // d
	}
	
	/**
	 * Generates a probable prime number. Extracted for testability so it can be overridden.
	 * @param bitLength bit length for the prime.
	 * @param random the random number generator.
	 * @return a BigInteger that is probably prime.
	 */
	protected BigInteger generatePrime(int bitLength, SecureRandom random) {
		// We use BigInteger.probablePrime, a standard and secure way to get large primes.
		return BigInteger.probablePrime(bitLength, random);
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