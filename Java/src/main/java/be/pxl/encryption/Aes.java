package be.pxl.encryption;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Aes {
	// An initialization vector (IV) or starting variable (SV)[5] is a block of
	// bits
	// that is used by several modes to randomize the encryption and hence to
	// produce
	// distinct ciphertexts even if the same message is encrypted multiple
	// times,
	// without the need for a slower re-keying process. It is important that an
	// initialization vector is never reused under the same key.

	// The IV size of AES should be 16 bytes or 128 bits (which is the block
	// size of AES-128).
	// If you use AES-256, the IV size should be 128 bits large, as the AES
	// standard allows for 128 bit block sizes only.
	// The original Rijndael algorithm allowed for other block sizes including
	// the 256 bit long block size.
	// String IV32Bytes = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	// private String encryptionKey1 = "0123456789abcdef"; //128 bits
	// private String encryptionKey2 = "0123456789abcdefghijklmn"; //192 bits
	// private String encryptionKey3 = "0123456789abcdef0123456789abcdef"; //256
	// bits

	// Cipher block modes
	// ------------------
	// CBC: Cipher Block Chaining. Each block of message is XORed with the
	// previous ciphertext block before being encrypted.
	// This way, each ciphertext block depends on all message blocks processed
	// up to that point.
	// To make each message unique, an initialization vector must be used (XOR)
	// in the first block.
	// Note: Wiki says CBC requires padding contrary to this working example.
	// ECB: Electronic Codebook, default implementation, not recommended, each
	// block encrypted seperatly from other blocks.

	// encrypt
	public byte[] encrypt(byte[] toEncrypt, SecretKey secret,
			KeySettings keySettings) throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchPaddingException, InvalidParameterSpecException {

		String algorithm = keySettings.getAlgorithm();
		if (algorithm.equals("PBKDF2WithHmacSHA1")
				|| algorithm.equals("PBKDF2WithHmacSHA512"))
			algorithm = Algorithm.AES_CBC_PKCS5PADDING.toString();		

		Cipher cipher = Cipher.getInstance(algorithm); // Cipher.getInstance("AES/CBC/PKCS5Padding");
		if (algorithm.equals("AES/ECB/PKCS5Padding")
				|| algorithm.equals("AES/ECB/NoPadding"))
			cipher.init(Cipher.ENCRYPT_MODE, secret);
		else
			cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(	
					keySettings.getIv()));

		return cipher.doFinal(toEncrypt);
	}

	// decrypt
	public byte[] decrypt(Message message, SecretKey secret,
			KeySettings keySettings) throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchPaddingException, InvalidParameterSpecException {

		String algorithm = keySettings.getAlgorithm();
		if (algorithm.equals("PBKDF2WithHmacSHA1")
				|| algorithm.equals("PBKDF2WithHmacSHA512"))
			algorithm = Algorithm.AES_CBC_PKCS5PADDING.toString();

		Cipher cipher = Cipher.getInstance(algorithm); // Cipher.getInstance("AES/CBC/PKCS5Padding");
		if (algorithm.equals("AES/ECB/PKCS5Padding")
				|| algorithm.equals("AES/ECB/NoPadding"))
			cipher.init(Cipher.DECRYPT_MODE, secret);
		else
			cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(
					keySettings.getIv()));

		return cipher.doFinal(message.getMessage());
	}

	public SecretKey createSecretKey(KeySettings keySettings)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchPaddingException,
			InvalidParameterSpecException {
		SecretKey secret;
		if (keySettings.getAlgorithm().equals("PBKDF2WithHmacSHA1")
				|| keySettings.getAlgorithm().equals("PBKDF2WithHmacSHA512")) {
			SecretKeyFactory factory = SecretKeyFactory.getInstance(keySettings
					.getAlgorithm()); // options see
										// http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory
			KeySpec spec = new PBEKeySpec( // password-based encryption
					keySettings.getPassword().toCharArray(), keySettings
							.getSalt().getBytes(), keySettings.getIterations(),
					keySettings.getKeySize());
			SecretKey tmp = factory.generateSecret(spec);
			secret = new SecretKeySpec(tmp.getEncoded(),
					keySettings.getAlgorithmName()); // getAlgorithmName() =
														// "AES"
			return secret;
		} else {
			KeyGenerator kgen = KeyGenerator.getInstance(keySettings
					.getAlgorithmName());
			kgen.init(keySettings.getKeySize());
			SecretKey key = kgen.generateKey();
			SecretKeySpec skeySpec = new SecretKeySpec(key.getEncoded(), "AES");
			return skeySpec;
		}
	}

	// Methods for printing
	public String printEncrypted(byte[] cipher) {
		return String.format("%-16s%s", "Encrypted: ", getString(cipher));
	}

	public String printDecrypted(byte[] message) {
		String text = "";
		try {
			text = new String(message, "UTF8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return String.format("%-16s%s", "Decrypted: ", text);
	}

	private String getString(byte[] cipher) {
		StringBuilder sb = new StringBuilder();
		for (byte i : cipher) {
			sb.append(i + " ");
		}
		return sb.toString();
	}

	// Main
	public static void main(String[] args) {

		String text = "abcdefghijklmnop"; // != 16 bytes will fail with nopadding
		Aes aes = new Aes();
		Message message;
		KeySettings keySettings = new KeySettings();
		keySettings.setAlgorithmName("AES");
		keySettings.setAlgorithm(Algorithm.PBKDF2WithHmacSHA512);
		keySettings.setKeySize(256);
		keySettings.setIterations(65536);
		keySettings.initPassword(32); // init methods generate random series
		keySettings.initSalt(16);
		keySettings.initIv(); // must always be 16 bytes
		SecretKey secret = null;
		try {
			secret = aes.createSecretKey(keySettings);
		} catch (Exception e1) {
			e1.printStackTrace();
		}

		// BEGIN
		try {
			byte[] encryptedMessage = aes.encrypt(Serializer.serialize(text),
					secret, keySettings);
			message = new Message(keySettings.getIv(), encryptedMessage);
			byte[] decryptedMessage = aes.decrypt(message, secret, keySettings);
			System.out.printf("%-16s%s\n", "Plain text:", text);
			System.out.println(aes.printEncrypted(encryptedMessage));
			System.out.println(aes.printDecrypted(decryptedMessage) + "\n");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}