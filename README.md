# SecureProperties
A simple encrypted properties implementation (needs Jasypt)

<pre>
public static void main(String[] args) throws IOException {
	SecureProperties sp = SecureProperties.createSecureProperties("file.txt");
	sp.setProperty("not.encrypted", "Readable value");
	sp.setEncryptedProperty("is.encrypted", "Unreadable value");
	sp.store();
}
</pre>
