package be.pxl.encryption;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class AES {
	//	An initialization vector (IV) or starting variable (SV)[5] is a block of bits 
	//	that is used by several modes to randomize the encryption and hence to produce 
	//	distinct ciphertexts even if the same plainText is encrypted multiple times, 
	//	without the need for a slower re-keying process. It is important that an 
	//	initialization vector is never reused under the same key.
	static String IV = "AAAAAAAAAAAAAAAA";
	
	//	The IV size of AES should be 16 bytes or 128 bits (which is the block size of AES-128).
	//	If you use AES-256, the IV size should be 128 bits large, as the AES standard allows for 128 bit block sizes only.
	//	The original Rijndael algorithm allowed for other block sizes including the 256 bit long block size.
//	static String IV32Bytes = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	
	static String plainText = "test text 123\0\0\0"; /* Note null padding */
	static String plainTextNoPadding = "test text 123";
	static String encryptionKey = "0123456789abcdef";

	public static void main(String[] args) {
		try {
			System.out.printf("%-16s%s\n", "Plain text:", plainText);

			byte[] cipher = encrypt(plainText, encryptionKey);
			byte[] cipherAes256 = encryptAes256(plainTextNoPadding, IV, encryptionKey);

			System.out.printf("%-16s","Cipher:");
			for (int i = 0; i < cipher.length; i++)
				System.out.print(new Integer(cipher[i]) + " ");
			System.out.println("");
			
			System.out.printf("%-16s","CipherAes256: ");
			for (int i = 0; i < cipherAes256.length; i++)
				System.out.print(new Integer(cipherAes256[i]) + " ");
			System.out.println("");
			
			String decrypted = decrypt(cipher, encryptionKey);
			String decryptedAes256 = decryptAes256(cipherAes256, IV, encryptionKey);

			System.out.printf("%-16s%s\n","Decrypt:", decrypted);
			System.out.printf("%-16s%s","DecryptAes256:", decryptedAes256);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static byte[] encrypt(String plainText, String encryptionKey) throws Exception {
		//	IBM invented the Cipher Block Chaining (CBC) mode of operation in 1976.
		//	In CBC mode, each block of plainText is XORed with the previous ciphertext block before being encrypted.
		//	This way, each ciphertext block depends on all plainText blocks processed up to that point.
		//	To make each message unique, an initialization vector must be used (XOR) in the first block.
		//	Note: Wiki says CBC requires padding contrary to this working example.
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE"); // SunJCE = Java Cryptographic Extension framework
		
		SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
		return cipher.doFinal(plainText.getBytes("UTF-8"));
	}

	public static String decrypt(byte[] cipherText, String encryptionKey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
		return new String(cipher.doFinal(cipherText), "UTF-8");
	}
	
	public static byte[] encryptAes256(String plainText, String IV, String encryptionKey){
		try {
            IvParameterSpec iv = new IvParameterSpec(IV.getBytes("UTF-8"));
            SecretKeySpec secretkeySpec = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretkeySpec, iv);
            byte[] encrypted = cipher.doFinal(plainText.getBytes());
            return Base64.encodeBase64(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
	}
	
	public static String decryptAes256(byte[] encrypted, String IV, String encryptionKey){
		try {
            IvParameterSpec iv = new IvParameterSpec(IV.getBytes("UTF-8"));
            SecretKeySpec secretkeySpec = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
            
			//	PKCS5Padding is interpreted as a synonym for PKCS7Padding in the cipher specification.
			//	It is simply a historical artifact, and rather than change it Sun decided to simply pretend 
			//	the PKCS5Padding means the same as PKCS7Padding when applied to block ciphers with a blocksize 
			//	greater than 8 bytes.
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            
            cipher.init(Cipher.DECRYPT_MODE, secretkeySpec, iv);
            byte[] decodedValue = new Base64().decode(encrypted);
            byte[] decryptedVal = cipher.doFinal(decodedValue);
            return new String(decryptedVal);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
	}
	
}
