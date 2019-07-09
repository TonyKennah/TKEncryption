# SecureProperties
A simple encrypted properties implementation (needs Jasypt)

public static void main(String[] args) throws IOException {
		SecureProperties sp = SecureProperties.createSecureProperties("file.txt");
		sp.setProperty("first.not.encypted", "Readable value");
		sp.setEncryptedProperty("first.is.encypted", "Unreadable value");
		sp.store();
}
