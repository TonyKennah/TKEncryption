package uk.co.kennah.encrypt;

public class Main {

	public static void main(String[] args) {
		SecureProperties sp = SecureProperties.getInstance("file.txt");
        sp.setProperty("not.encrypted", "Readable value");
        sp.setEncryptedProperty("is.encrypted", "This will be unreadable in the file");

        // Save to the file
        sp.store();

        // Reading properties
        System.out.println(sp.getProperty("is.encrypted")); // Prints the decrypted value

	}

}
