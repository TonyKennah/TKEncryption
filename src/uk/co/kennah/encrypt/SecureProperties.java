package uk.co.kennah.encrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.properties.EncryptableProperties;
import uk.co.kennah.encrypt.utils.KeGen;
import uk.co.kennah.encrypt.utils.PaGen;

/**
 * {@link uk.co.kennah.encrypt.SecureProperties SecureProperties} replaces the conventional Properties file by making use of
 * the <a href="http://www.jasypt.org/javadoc.html">jasypt API</a> to create an encrypted properties file.  The password for
 * unlocking the encrypted content is contained within the file BUT itself is encrypted.
 * 
 * @author Tony Kennah
 */
public class SecureProperties {

	private static final String TOKENS = "TK.ACCESS.AUTHENTICATION.TOKENS";
	private String filename;
	private Properties prop;
	private List<String> encProps;
	private String tokenValue;
	
	/**
	 * Returns a SecureProperties object that can then be used to store encrypted content. 
	 * 
	 * {@link uk.co.kennah.encrypt.utils.PaGen PaGen} is used to generate a random password.
	 * 
	 * createSecureProperties is the only way to instantiate a new secure properties
	 * 
	 * <p>
	 * If the filename passed to this static initialiser exists and contains
	 * Authentication Tokens (an encrypted password), the tokens found will be used.
	 * If the filename passed to this static initialiser exists and DOES NOT contain
	 * Authentication Tokens, the tokens will be produced.
	 * If the filename passed to this static initialiser doesn't exist a new file will be
	 * eventually be created containing tokens.
	 * 
	 * @return      		the secure property file awaiting encrypted content
	 * @see         		java.util.Properties Properties
	 * @param filename		the path\filename to be used
	 */
	public static SecureProperties createSecureProperties(String filename){
		if(new File(filename).isFile()) {
			Properties toConvert = loadProperties(new Properties(), filename);
			if(toConvert.getProperty(TOKENS)==null){
				toConvert.setProperty(TOKENS, crypto(PaGen.pas()));
				writePropertiesFile(toConvert, filename);
			}			
		}
		return new SecureProperties(filename);
	}
		
	/**
	 * keySet get the Set of keys
	 * 
	 * @return returns the keyset from the underlying property list
	 */
	public Set<Object> keySet() {
		return prop.keySet();
	}

	/**
	 * Set the property
	 * 
	 * @param key			String to be used as the key
	 * @param value			String to be used as the value for this key value pair
	 * @return 			the previous value of the specified key in this property list, or null if it did not have one.
	 */
	public Object setProperty(String key, String value){
		return prop.setProperty(key, value);
	}
	
	/**
	 * Set the property BUT make sure this is eventually encrypted so we add this key to the 
	 * java.util.List of encrypted contents / values for later use in store().  This method makes use 
	 * of the standard setProperty() method of this object. 
	 * 
	 * @param key			String to be used as the key
	 * @param value			String to be used as the value for this key value pair
	 * @return 			the previous value of the specified key in this property list, or null if it did not have one.
	 *				Comes directly from the setProperty() method
	 */
	public Object setEncryptedProperty(String key, String value) {
		encProps.add(key);
		return setProperty(key, value);
	}
	
	/**
	 * Get the property
	 * 
	 * @param key			String to be used as the key
	 * @return 			String which this key points at from the underlying property list.
	 */
	public String getProperty(String key) {
		return prop.getProperty(key);
	}
	
	/**
	 * store	gets the property list ready for writing to disk and
	 * then calls the private internal writePropertiesFile method to
	 * actually write this list to permanent storage.
	 */
	public void store(){
		Properties p = new Properties();
		/* Java 8 V Java 7 = side effects = Java 7 wins
		prop.keySet().stream()
			.filter( e -> encProps.contains(e.toString()))
			.forEach( e -> p.setProperty(e.toString(), encrypt(prop.getProperty(e.toString()))));
		prop.keySet().stream()
			.filter( e -> !encProps.contains(e.toString()))
			.forEach( e -> p.setProperty(e.toString(), prop.getProperty(e.toString())));*/
		for(Object k : prop.keySet()) {
			if(encProps.contains(k.toString()))
				p.setProperty(k.toString(), encrypt(prop.getProperty(k.toString())));
			else
				p.setProperty(k.toString(), prop.getProperty(k.toString()));
		}
		writePropertiesFile(p, filename);
	}

	
	private SecureProperties(String filename){
		this.filename = filename;
		encProps = new ArrayList<>();
		StandardPBEStringEncryptor enc = new StandardPBEStringEncryptor();
		if(!new File(filename).isFile()) {
			String pas = PaGen.pas();
			Properties p = new Properties();
			p.setProperty(TOKENS, crypto(pas));
			writePropertiesFile(p, filename);
			enc.setPassword(pas);
		}
		else {
			enc.setPassword(decrypt());
		}
		this.prop = new EncryptableProperties(enc);
		loadProperties(prop, filename);
	}
	
	private String encrypt(String token){
		return "ENC(" + encryptor(decrypt()).encrypt(token) + ")";
	}
	
	private String decrypt(List<String> t) {
		return t.stream()
				.limit(t.size() - 2)
				.map(e -> new BigInteger(e))
				.map(i -> i.modPow(new BigInteger(t.get(t.size() - 2)),
						   new BigInteger(t.get(t.size() - 1))))
				.map(c -> (char) c.byteValue())
				.map(String::valueOf)
				.collect(Collectors.joining(""));
	}
	
	private String decrypt() {
		if(tokenValue==null)
			tokenValue = decrypt(Arrays.asList(loadProperties(new Properties(), filename).getProperty(TOKENS).split(",")));
		return tokenValue;
	}
	
	private static void writePropertiesFile(Properties p, String filename){
		try(OutputStream os = new FileOutputStream(new File(filename))) {
			p.store(os, "Do not edit the "+TOKENS+" or any ENC() constants");
			os.flush();
		}
		catch (IOException e) {	throw new RuntimeException("Properties couldn't be written!"); }
	}
	
	private static Properties loadProperties(Properties prop, String filename){
		try(InputStream is = new FileInputStream(new File(filename))) {
			prop.load(is);	
		}
		catch (IOException e) {	throw new RuntimeException("Properties couldn't be loaded!"); }
		return prop;
	}
	
	private static String crypto(String passwd) {
		KeGen kg = new KeGen(12);
		StringBuffer enc = new StringBuffer();
		for(byte b : passwd.getBytes())
			enc.append(new BigInteger(new byte[]{b}).modPow(kg.pub(), kg.sig())+",");	
		enc.append(kg.pri()+",");
		enc.append(kg.sig());	
		return enc.toString();
	}
	
	private static StandardPBEStringEncryptor encryptor(String passwd) {
		StandardPBEStringEncryptor enc = new StandardPBEStringEncryptor();
		enc.setPassword(passwd);
		return enc;
	}
}
