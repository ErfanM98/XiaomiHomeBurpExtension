package burp;

import java.security.MessageDigest;
import java.util.Base64;

public class RC4 {
	

	public static char[] rc4mi(char[] data, char[] key) {
		
		char[] S = new char[256];
		for (int i = 0; i < 256; S[i] = (char) i, i++);
		int j = 0;
		
		char[] out = new char[data.length];
		
		
		for (int i = 0; i < 256; i++) {
			j = (j + key[i % key.length] + S[i]) % 256;

			char tmp = S[i];
			S[i] = S[j];
			S[j] = tmp;
			
		}

		
		int i = 0;
		j = 0;
		for (int x = 0; x < 1024; x++) {
			
			i = (i + 1) % 256;
			j = (j + S[i]) % 256;
			char tmp = S[i];
			S[i] = S[j];
			S[j] = tmp;
			
		}
		
		int k = 0;
		for (char ch : data) {
			i = (i + 1) % 256;
			j = (j + S[i]) % 256;
			char tmp = S[i];
			S[i] = S[j];
			S[j] = tmp;
			out[k] = (char) (ch ^ S[(S[i] + S[j]) % 256]);
			k++;
			
		}
		
        return out;
    }

    public static String createKey(String ssecurity, String nonce) throws Exception {
        byte[] key = Base64.getDecoder().decode(ssecurity);
        byte[] nonceBytes = Base64.getDecoder().decode(nonce);
        byte[] combined = new byte[key.length + nonceBytes.length];
        System.arraycopy(key, 0, combined, 0, key.length);
        System.arraycopy(nonceBytes, 0, combined, key.length, nonceBytes.length);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(combined);
        return Base64.getEncoder().encodeToString(hash);
    }
    
    public static String decrypt(String base64EncryptedMessage, String base64key) {
    	
    	
    	byte[] encryptedMessage = Base64.getDecoder().decode(base64EncryptedMessage);
        byte[] key = Base64.getDecoder().decode(base64key);
        
        char[] emch = new char[encryptedMessage.length];
        
        for (int i = 0; i < encryptedMessage.length;i ++) {
        	emch[i] = (char) (encryptedMessage[i] & 0xFF);
        }
        
        char[] kch = new char[key.length];
        
        for (int i = 0; i < key.length;i ++) {
        	kch[i] = (char) (key[i] & 0xFF);
        }
        
        
    	
		return String.valueOf(rc4mi(emch, kch));
    	
    }
    
    
    public static String decrypt(String base64EncryptedMessage, String base64Nonce, String base64SecretKey) throws Exception {
    	return decrypt(base64EncryptedMessage, createKey(base64SecretKey, base64Nonce));
    }


}
