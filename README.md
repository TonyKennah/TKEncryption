# SecureProperties
A simple encrypted properties implementation (needs Jasypt http://www.jasypt.org/) with the jasypt encryption password encrypted asymmetrically and stored within the same file :)

<pre>
public static void main(String[] args) throws IOException {
	SecureProperties sp = SecureProperties.createSecureProperties("file.txt");
	sp.setProperty("not.encrypted", "Readable value");
	sp.setEncryptedProperty("is.encrypted", "Unreadable value");
	sp.store();
	
	//Getting Properties
	//for(Object key : sp.keySet()) {
	//	System.out.println(key.toString() +"="+ sp.getProperty(key.toString()));
	//}
}

Produces: file.txt

#Do not edit the TK.ACCESS.AUTHENTICATION.TOKENS or any ENC() constants
#Tue Jul 09 20:22:07 BST 2019
TK.ACCESS.AUTHENTICATION.TOKENS=4107962,6995037,2563313,415094,6995037,6826570,6302193,6879550,3764443,8789633
is.encrypted=ENC(nuBxX15FoNraJ9lrL8LFbMNhYuc+p4tnRCbfJALzTII\=)
not.encrypted=Readable value
</pre>
