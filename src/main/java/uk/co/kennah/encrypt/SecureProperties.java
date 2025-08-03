package uk.co.kennah.encrypt;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.properties.EncryptableProperties;

/**
 * {@link uk.co.kennah.encrypt.SecureProperties SecureProperties} replaces the conventional Properties file by making use of
 * the <a href="http://www.jasypt.org/javadoc.html">jasypt API</a> to create an encrypted properties file.
 * 
 * @author Tony Kennah
 */
public class SecureProperties {
	
	private final Properties properties;
	private final StandardPBEStringEncryptor encryptor;
	private final String filename;
	
	public SecureProperties(String filename, String password) {
		this.filename = filename;
		this.encryptor = createEncryptor(password);
		this.properties = new EncryptableProperties(encryptor);
		load();
	}
		
	/**
	 * keySet get the Set of keys
	 * 
	 * @return returns the keyset from the underlying property list
	 */
	public Set<String> keySet() {
		return properties.keySet().stream().map(Object::toString).collect(Collectors.toSet());
	}

	/**
	 * Set the property
	 * 
	 * @param key			String to be used as the key
	 * @param value			String to be used as the value for this key value pair
	 */
	public void setProperty(String key, String value){
		properties.setProperty(key, value);
	}
	
	/**
	 * Sets a property that will be stored in encrypted format.
	 * 
	 * @param key			String to be used as the key
	 * @param value			String to be used as the value for this key value pair
	 */
	public void setEncryptedProperty(String key, String value) {
		properties.setProperty(key, "ENC(" + encryptor.encrypt(value) + ")");
	}
	
	/**
	 * Get the property
	 * 
	 * @param key			String to be used as the key
	 * @return 			The decrypted property value, or the plain text value.
	 */
	public String getProperty(String key) {
		return properties.getProperty(key);
	}
	
	/**
	 * Writes the properties to the file. Encrypted values are stored with
	 * the `ENC(...)` wrapper.
	 */
	public void store(){
		try (OutputStream os = new FileOutputStream(filename)) {
			properties.store(os, "Secure Properties File");
		} catch (IOException e) {
			throw new RuntimeException("Failed to store properties to file: " + filename, e);
		}
	}
	
	private void load() {
		File file = new File(filename);
		if (file.exists()) {
			try (FileReader reader = new FileReader(file)) {
				properties.load(reader);
			} catch (IOException e) {
				throw new RuntimeException("Failed to load properties from file: " + filename, e);
			}
		}
	}
	
	/**
	 * This method simply sets a password on an org.jasypt.encryption.pbe.StandardPBEStringEncryptor 
	 * and returns that Encryptor.
	 */
	private static StandardPBEStringEncryptor createEncryptor(String password) {
		StandardPBEStringEncryptor enc = new StandardPBEStringEncryptor();
		enc.setPassword(password);
		enc.setAlgorithm("PBEWITHHMACSHA512ANDAES_256");
		enc.setIvGenerator(new org.jasypt.iv.RandomIvGenerator());
		return enc;
	}
}
