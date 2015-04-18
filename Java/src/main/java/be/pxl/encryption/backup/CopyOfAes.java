package be.pxl.encryption.backup;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import be.pxl.encryption.Algorithm;
import be.pxl.encryption.KeySettings;
import be.pxl.encryption.Message;

public class CopyOfAes implements Serializable {
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
	public byte[] encrypt(String message, KeySettings keySettings)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException,
			UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchPaddingException,
			InvalidParameterSpecException

	{
		SecretKey secret = createSecretKey(keySettings);
		/* Encrypt the message. */
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(
				keySettings.getIv()));

		// // Get iv from cypher not needed here because we make the IV in main
		// for encrypt and decrypt
		// AlgorithmParameters params = cipher.getParameters();
		// byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

		return cipher.doFinal(message.getBytes("UTF-8"));
	}

	// encrypt
	public byte[] encrypt(Object message, KeySettings keySettings)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException,
			UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchPaddingException,
			InvalidParameterSpecException

	{
		SecretKey secret = createSecretKey(keySettings);
		/* Encrypt the message. */
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(
				keySettings.getIv()));
		return null;
		// return cipher.doFinal(Convert.toByteArray(message));
	}

	// decrypt
	public String decrypt(byte[] encrypted, KeySettings keySettings)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException,
			UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchPaddingException,
			InvalidParameterSpecException {
		SecretKey secret = createSecretKey(keySettings);
		/* Decrypt the message, given derived key and initialization vector. */
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(
				keySettings.getIv()));
		String message = new String(cipher.doFinal(encrypted), "UTF-8");

		return message;
	}

	public byte[] encrypt(String message, SecretKey secretKey,
			KeySettings keySetting) throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchPaddingException, InvalidParameterSpecException

	{
		/* Encrypt the message. */
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		AlgorithmParameters params = cipher.getParameters();
		// Deliver this IV to recepient
		keySetting
				.setIv(params.getParameterSpec(IvParameterSpec.class).getIV());

		return cipher.doFinal(message.getBytes("UTF-8"));
	}

	public String decrypt(byte[] encrypted, SecretKey secretKey,
			KeySettings keySetting) throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchPaddingException, InvalidParameterSpecException {
		/* Decrypt the message, given derived key and initialization vector. */
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(
				keySetting.getIv()));
		// cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
		String message = new String(cipher.doFinal(encrypted), "UTF-8");

		return message;
	}

	public String decrypt(Message message, SecretKey secretKey)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException,
			UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchPaddingException,
			InvalidParameterSpecException {
		/* Decrypt the message, given derived key and initialization vector. */
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey,
				new IvParameterSpec(message.getIv()));
		// cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
		String decrypted = new String(cipher.doFinal(message.getMessage()),
				"UTF-8");

		return decrypted;
	}

	public SecretKey createSecretKey(KeySettings keySettings)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchPaddingException,
			InvalidParameterSpecException {
		String alg = keySettings.getAlgorithm();
		SecretKeyFactory factory = SecretKeyFactory.getInstance(keySettings
				.getAlgorithm()); // options see
									// http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory
		KeySpec spec = new PBEKeySpec( // password-based encryption
				keySettings.getPassword().toCharArray(), keySettings.getSalt()
						.getBytes(), keySettings.getIterations(),
				keySettings.getKeySize());
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(),
				keySettings.getAlgorithmName()); // getAlgorithmName() = "AES"
		return secret;
	}

	// Methods for printing
	private String printEncrypted(byte[] cipher) {
		return String.format("%-16s%s", "Encrypted: ", getString(cipher));
	}

	private String printDecrypted(String message) {
		return String.format("%-16s%s", "Decrypted: ", message);
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
		String text = "jos";
		CopyOfAes aes = new CopyOfAes();
		Message message;
		KeySettings keySettings = new KeySettings();

		keySettings.setAlgorithmName("AES");
		keySettings.setAlgorithm(Algorithm.PBKDF2WithHmacSHA512);
		keySettings.setPassword("0123456789abcdef0123456789abcdef");
		keySettings.setSalt("imma salt!");
		keySettings.setKeySize(256);
		keySettings.setIterations(65536);
		keySettings.initIv();

		try {
			byte[] encryptedMessage = aes.encrypt(text, keySettings);
			String decryptedMessage = aes
					.decrypt(encryptedMessage, keySettings);

			System.out.printf("%-16s%s\n", "Plain text:", text);
			System.out.println(aes.printEncrypted(encryptedMessage));
			System.out.println(aes.printDecrypted(decryptedMessage) + "\n");

			SecretKey secret = aes.createSecretKey(keySettings);
			encryptedMessage = aes.encrypt(text, secret, keySettings);
			message = new Message(keySettings.getIv(), encryptedMessage);
			decryptedMessage = aes.decrypt(message, secret);
			// decryptedMessage = aes.decrypt(encryptedMessage, secret,
			// keySettings);
			System.out.println(aes.printEncrypted(encryptedMessage));
			System.out.println(aes.printDecrypted(decryptedMessage) + "\n");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}

// public byte[] encrypt(String message, String encryptionKey) throws Exception
// {
// // Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE"); //
// SunJCE = Java Cryptographic Extension framework
// Cipher cipher = Cipher.getInstance(Algorithm.AES_CBC_PKCS5PADDING.get(),
// "SunJCE");
// SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"),
// "AES");
// cipher.init(Cipher.ENCRYPT_MODE, key, new
// IvParameterSpec(IV.getBytes("UTF-8")));
// return cipher.doFinal(message.getBytes("UTF-8"));
// }
//
// public byte[] encrypt2(String message, String encryptionKey, Algorithm
// algorithm) throws Exception {
// Cipher cipher = Cipher.getInstance(algorithm.get(), "SunJCE"); // SunJCE =
// Java Cryptographic Extension framework
// SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"),
// "AES");
// cipher.init(Cipher.ENCRYPT_MODE, key, new
// IvParameterSpec(IV.getBytes("UTF-8")));
// return cipher.doFinal(message.getBytes("UTF-8"));
// }
//
// public String decrypt(byte[] cipherText, String encryptionKey) throws
// Exception {
// Cipher cipher = Cipher.getInstance(Algorithm.AES_CBC_PKCS5PADDING.get(),
// "SunJCE");
// SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"),
// "AES");
// cipher.init(Cipher.DECRYPT_MODE, key, new
// IvParameterSpec(IV.getBytes("UTF-8")));
// return new String(cipher.doFinal(cipherText), "UTF-8");
// }
//
// public byte[] encrypt256(String message, String IV, String encryptionKey){
// try {
// IvParameterSpec iv = new IvParameterSpec(IV.getBytes("UTF-8"));
// SecretKeySpec secretkeySpec = new
// SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
// Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
// cipher.init(Cipher.ENCRYPT_MODE, secretkeySpec, iv);
// byte[] encrypted = cipher.doFinal(message.getBytes());
// return Base64.encodeBase64(encrypted);
// } catch (Exception ex) {
// ex.printStackTrace();
// }
// return null;
// }
//
// public String decrypt256(byte[] encrypted, String IV, String encryptionKey){
// try {
// IvParameterSpec iv = new IvParameterSpec(IV.getBytes("UTF-8"));
// SecretKeySpec secretkeySpec = new
// SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
// Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING"); // PKCS5Padding
// is interpreted as a synonym for PKCS7Padding in the cipher specification for
// ciphers with a blocksize
// // greater than 8 bytes.
// cipher.init(Cipher.DECRYPT_MODE, secretkeySpec, iv);
// byte[] decodedValue = new Base64().decode(encrypted);
// byte[] decryptedVal = cipher.doFinal(decodedValue);
// return new String(decryptedVal);
// } catch (Exception ex) {
// ex.printStackTrace();
// }
// return null;
// }

// private int[] getInts(byte[] cipher) {
// int[] asciiNumbers = new int[cipher.length];
// for (int i = 0; i < cipher.length; i++)
// asciiNumbers[i] = cipher[i];
// return asciiNumbers;
// }

