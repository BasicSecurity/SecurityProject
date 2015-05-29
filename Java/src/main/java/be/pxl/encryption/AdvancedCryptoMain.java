package be.pxl.encryption;

import javax.crypto.SecretKey;

public class AdvancedCryptoMain {
	public static void main(String[] args) {
		AdvancedCrypto c = new AdvancedCrypto();

		try {
			String clearText = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnop"; // != 16 bytes will fail with no
												// padding.
			String encrypted, decrypted;
			String password = "joske";
			
			SecretKey secret = c.getSecretKey(password, c.generateSalt());
			
			System.out.println("Clear text: " + clearText);
			
			encrypted = c.encrypt(secret, clearText);
			System.out.println("Encrypted: " + encrypted);
			
			decrypted = c.decrypt(secret, encrypted);
			System.out.println("Decrypted: " + decrypted);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
