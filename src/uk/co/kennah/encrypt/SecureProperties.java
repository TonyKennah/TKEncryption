package uk.co.kennah.encrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLClassLoader;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
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

	//TOKENS - is just a label that will be used within a secured property file
	//	as a key for a set of encrypted values (the key for the file)
	private static final String TOKENS = "TK.ACCESS.AUTHENTICATION.TOKENS";
	
	//originalProperties - is either existing and provided in or we fail
	private Properties originalProperties;
	
	//encryptedProperties - when all is complete this will be used to store key / values
	private Properties encryptedProperties;
	
	//listOfEncrytpedPropertyKeys - records all keys whose value will need to be encrypted
	private List<String> listOfEncrytpedPropertyKeys;
		
	//an in memory reference to the encrypted key for this file
	private String tokenValue;
	
	//the name of the file which is the focus of code
	private String filename;
	
	/**
	 * Returns a SecureProperties object that can then be used to store encrypted content. 
	 * 
	 * {@link uk.co.kennah.encrypt.utils.PaGen PaGen} is used to generate a random password.
	 * 
	 * SecureProperties.getInstance("filename"); is the only way to instantiate a new secure properties
	 * 
	 * <p>
	 * If the filename passed to this static initialiser exists and contains
	 * Authentication Tokens (an encrypted password), the tokens found will be used.
	 * If the filename passed to this static initialiser exists and DOES NOT contain
	 * Authentication Tokens, the tokens will be produced.
	 * If the filename passed to this static initialiser doesn't exist we fail
	 * 
	 * @return      		the secure property file awaiting encrypted content
	 * @see         		java.util.Properties Properties
	 * @param filename		the path\filename to be used
	 * @throws URISyntaxException 
	 */
	public static SecureProperties getInstance(String filename){
		if(new File(checkPathForFile(filename)).isFile()) {
			Properties toConvert = loadProperties(new Properties(), filename);
			if(toConvert.getProperty(TOKENS)==null){
				toConvert.setProperty(TOKENS, encrypt(PaGen.generateValidPassword()));
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
	public Set<String> keySet() {
		return originalProperties.keySet().stream().map( e -> e.toString() ).collect(Collectors.toSet());
	}

	/**
	 * Set the property
	 * 
	 * @param key			String to be used as the key
	 * @param value			String to be used as the value for this key value pair
	 * @return 			the previous value of the specified key in this property list, or null if it did not have one.
	 */
	public String setProperty(String key, String value){
		Object o = originalProperties.setProperty(key, value);
		return o == null ? "" : o.toString();
	}
	
	/**
	 * Set the property BUT make sure this is eventually encrypted so we add this key to the 
	 * java.util.List of encrypted contents / values for later use in store().  This method makes use 
	 * of the standard setProperty() method of this object. 
	 * 
	 * @param key			String to be used as the key
	 * @param value			String to be used as the value for this key value pair
	 * @return 			the previous value of the specified key in this property list, or null if it did not have one.
	 * 				Comes directly from the setProperty() method
	 */
	public String setEncryptedProperty(String key, String value) {
		listOfEncrytpedPropertyKeys.add(key);
		return setProperty(key, value).toString();
	}
	
	/**
	 * Get the property
	 * 
	 * @param key			String to be used as the key
	 * @return 			String which this key points at from the underlying property list.
	 * @throws			RuntimeException (with nice message) - if jasypt has a problem
	 */
	public String getProperty(String key) {
		try {
			return originalProperties.getProperty(key);
		}
		catch(EncryptionOperationNotPossibleException e) {
			throw new RuntimeException("Properties file has become corrupt!\n\t"
					+ "Either an ENC() tagged value has been modified or " + TOKENS + "\n" 
					+ "Exception:\n\tEncryptionOperationNotPossibleException\n"
					+ "Message:\n\t"
					+ e.getMessage()
					+ "\nStackTrace:\n"
					+ Stream.of(e.getStackTrace())
						.map( f -> "\t"+f.toString()+"\n")
						.collect(Collectors.joining("")));
		}
	}
	
	/**
	 * store	gets the property list ready for writing to disk using
	 * the private mapper method to either encrypt or not encrypt the values
	 * then calls the private internal writePropertiesFile method to
	 * actually write this list to permanent storage.
	 */
	public void store(){
		encryptedProperties = new Properties();
		originalProperties.keySet().stream()
			.map( e -> e.toString() )
			.map(this::mapOriginalPropToSecuredProp)
			.collect(Collectors.toList());
		writePropertiesFile(encryptedProperties, filename);
	}
	
							//private instance methods//
	/**
	 * private constructor	-	Sets up a couple of our global attributes
	 * Directly
	 * 		filename, originalProperties, listOfEncrytpedPropertyKeys
	 * Indirectly
	 * 		tokenValue
	 * Of our 5 global attributes only 1 'encryptedProperties' isn't instantiated
	 */
	private SecureProperties(String filename){
		this.filename = filename;
		StandardPBEStringEncryptor enc = new StandardPBEStringEncryptor();
		enc.setPassword(decrypt());
		this.originalProperties = new EncryptableProperties(enc);
		loadProperties(originalProperties, filename);
		
		Properties p = loadProperties(new Properties(), filename);
		listOfEncrytpedPropertyKeys = p.keySet().stream()
				.filter( e -> p.get(e).toString().contains("ENC(") )
				.map( e -> e.toString())
				.collect(Collectors.toList());
	}

	/**
	 * Mapper - deciding whether to set an encrypted token or an unencrypted token
	 * 		uses listOfEncrytpedPropertyKeys List to decide
	 * 
	 * @param	String key 	-	The key that holds the possibly encrypted value
	 * @return	String		-	The previous value of the specified key in this propertylist, or
	 *					null if it did not have one.
	 */
	private Object mapOriginalPropToSecuredProp(String key) {
		if(listOfEncrytpedPropertyKeys.contains(key))
			return encryptedProperties.setProperty(key, encryptToken(originalProperties.getProperty(key)));
		return encryptedProperties.setProperty(key, originalProperties.getProperty(key));
	}
	
	/**
	 * Uses the password stored within the properties file to encrypt the token being provided
	 * and wraps the encrypted token in ENC() tags as standard
	 * 
	 * @param	String token 	- 	String to be encrypted
	 * @return	String		-	encrypted Sting within ENC() tag
	 */
	private String encryptToken(String token){
		return "ENC(" + encryptor(decrypt()).encrypt(token) + ")";
	}
	
	/**
	 * Takes a list of stings and converts them via maths then joins them into a single string
	 * 
	 * @param 	List<String>
	 * @return	String - joined up and manipulated elements of input param 
	 */
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
	
	/**
	 * Returns the file tokenValue / password if it is set or sets it first if not.
	 */
	private String decrypt() {
		if(tokenValue==null)
			tokenValue = decrypt(Arrays.asList(loadProperties(new Properties(), filename).getProperty(TOKENS).split(",")));
		return tokenValue;
	}
	
										//private static methods//
	
	/**
	 * Return the current CLASSPATH entries excluding jar files
	 */
	private static String createExceptionMessage() {
		return Stream.of(((URLClassLoader)ClassLoader.getSystemClassLoader()).getURLs())
				.filter( e -> !e.toString().toLowerCase().endsWith(".jar"))
				.map( e -> "   "+e.toString()+"\n")
				.collect(Collectors.joining(""));
	}
	
	/**
	 * Check to see if we can read the provided resource
	 */
	private static URI checkPathForFile(String filename){
		if(SecureProperties.class.getClassLoader().getResource(filename) != null)
			try {
				return SecureProperties.class.getClassLoader().getResource(filename).toURI();
			} catch (URISyntaxException e) {
				e.printStackTrace();
			}
		else
			throw new RuntimeException("The file called <<" + filename + ">> couldn't be found on CLASSPATH.\n"
					+ "Try adding the location of the file to your CLASSPATH or "
					+ "moving\\creating the file on the defined CLASSPATH\n\nCLASSPATH:\n" + createExceptionMessage());
		return null;
	}
	
	/**
	 * Writes a Properties file to disk
	 */
	private static void writePropertiesFile(Properties p, String filename){
		try(OutputStream os = new FileOutputStream(new File(checkPathForFile(filename)))) {
			p.store(os, "Do not edit the "+TOKENS+" or any ENC() constants");
			os.flush();
		}
		catch (Exception e){ throw new RuntimeException("Properties couldn't be written!"); } 
	}
	
	/**
	 * Reads and loads up a Properties file from disk
	 */
	private static Properties loadProperties(Properties prop, String filename){
		try(InputStream is = new FileInputStream(new File(checkPathForFile(filename)))) {
			prop.load(is);	
		}
		catch (Exception e) {	throw new RuntimeException("Properties couldn't be loaded!"); }
		return prop;
	}
	
	/**
	 * Uses KeGen class to help encrypt the provided String which, once encrypted, is returned 
	 */
	private static String encrypt(String passwd) {
		KeGen kg = new KeGen(12);
		StringBuffer enc = new StringBuffer();
		for(byte b : passwd.getBytes())
			enc.append(new BigInteger(new byte[]{b}).modPow(kg.pub(), kg.sig())+",");	
		enc.append(kg.pri()+","+kg.sig());	
		return enc.toString();
	}
	
	/**
	 * This method simply sets a password on an org.jasypt.encryption.pbe.StandardPBEStringEncryptor 
	 * and returns that Encryptor.
	 */
	private static StandardPBEStringEncryptor encryptor(String passwd) {
		StandardPBEStringEncryptor enc = new StandardPBEStringEncryptor();
		enc.setPassword(passwd);
		return enc;
	}
}
