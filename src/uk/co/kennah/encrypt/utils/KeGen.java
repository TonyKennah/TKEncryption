package uk.co.kennah.encrypt.utils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author Tony Kennah
 */
public class KeGen {
	
	private BigInteger sig;
	private BigInteger pri;
	private BigInteger pub;

	public KeGen(int bitlen) {
		SecureRandom random = new SecureRandom();
		BigInteger prime1 = new BigInteger(bitlen, 100, random);
		BigInteger prime2 = new BigInteger(bitlen, 100, random);

		while (prime2.intValue() == prime1.intValue())
			prime2 = new BigInteger(bitlen, 100, random);
		sig = prime1.multiply(prime2);
		BigInteger sumOfOneLower = (prime1.subtract(BigInteger.ONE)).multiply(prime2.subtract(BigInteger.ONE));
		pub = new BigInteger("3");
		
		while(sumOfOneLower.gcd(pub).intValue() > 1)
			pub = pub.add(new BigInteger("2"));
		pri = pub.modInverse(sumOfOneLower);
	}
	
	public BigInteger sig() {
		return sig;
	}
	
	public BigInteger pub() {
		return pub;
	}
	
	public BigInteger pri() {
		return pri;
	}
}