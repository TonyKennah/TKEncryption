package uk.co.kennah.encrypt.utils;

import java.util.Random;
import java.util.function.IntPredicate;
import java.security.SecureRandom;
 
/**
 * @author Tony Kennah
 */
public class PaGen {
	
    private static final Random RANDOM = new SecureRandom();
    private static final String NUMBER = "0123456789";
    private static final String ALPHA_U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String ALPHA_L = "abcdefghijklmnopqrstuvwxyz";
    private static final String SPECIAL = "_*!";
    private static final int LENGTH = 8;
    
    public static String generateValidPassword() {
    	String pass = generatePassword();
    	while(!isValid(pass)) {
    		pass = generatePassword();
    	}
    	return pass;
    }
    
    private static String generatePassword() {
    	StringBuilder returnValue = new StringBuilder(LENGTH);
        for (int i = 0; i < LENGTH-1; i++) {
        	if(i == 0)
        		returnValue.append(ALPHA_U.charAt(RANDOM.nextInt(ALPHA_U.length())));
        	else {
        		Random ran = new Random(); 
                	int nxt = ran.nextInt(3);
                	if(nxt == 0)
                		returnValue.append(ALPHA_L.charAt(RANDOM.nextInt(ALPHA_L.length())));
                	else if(nxt == 1)
                		returnValue.append(ALPHA_U.charAt(RANDOM.nextInt(ALPHA_U.length())));
                	else if(nxt == 2)
                		returnValue.append(NUMBER.charAt(RANDOM.nextInt(NUMBER.length())));
        	}
        }
        Random rand = new Random();
        int randomNum = rand.nextInt(((LENGTH-2) - 1) + 1) + 1;
        returnValue.replace(randomNum, randomNum, ""+SPECIAL.charAt(RANDOM.nextInt(SPECIAL.length())));
		return new String(returnValue);
    }
    
    private static boolean isValid(String value) {
    	return 	contains(value, i -> Character.isLetter(i) && Character.isLowerCase(i)) && 
    		contains(value, i -> Character.isLetter(i) && Character.isUpperCase(i)) && 
    		contains(value, Character::isDigit);
    }
    
    private static boolean contains(String value, IntPredicate predicate) {
        return value.chars().anyMatch(predicate);
    }
}
