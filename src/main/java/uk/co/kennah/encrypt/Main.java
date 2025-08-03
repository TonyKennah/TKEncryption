package uk.co.kennah.encrypt;

public class Main {

	public static void main(String[] args) {
		// The master password should be retrieved from a secure location,
		// such as an environment variable or a secrets management service.
		// For this example, we'll hardcode it.
		String masterPassword = "a-very-secret-master-password";

		// The properties file will be created in the application's working directory.
		SecureProperties sp = new SecureProperties("secure.properties", masterPassword);

		// Set some properties
        sp.setProperty("not.encrypted", "Readable value");
        sp.setEncryptedProperty("is.encrypted", "This will be unreadable in the file");

        // Save to the file
        sp.store();
        System.out.println("Properties saved to secure.properties");

        // Reading properties
        System.out.println(sp.getProperty("is.encrypted")); // Prints the decrypted value
	}
}
