// http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
// http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyGenerator

package be.pxl.encryption;

import static be.pxl.encryption.FileManager.getCurrentDirectory;
import static be.pxl.encryption.FileManager.saveConfiguration;
import static be.pxl.encryption.FileManager.loadConfiguration;
import static be.pxl.encryption.FileManager.keyToString;
import static be.pxl.encryption.FileManager.stringToKey;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.TreeMap;

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

public class Aes implements Serializable {
	// Main
	public static void main(String[] args) {
		String plainText = "abcdefghijklmno";
		String decryptedText;
		byte[] cipherText;
		// Key-Value pairs for writing key with configuration to XML.
		TreeMap<String, String> keyConfig = new TreeMap<String, String>();
		TreeMap<String, String> keyConfig1 = new TreeMap<String, String>();

		try {

			// ======================================= \\
			// Encryption/decryption with key in RAM \\
			// ======================================= \\

			Aes aes = new Aes();
			Aes aesLocal = new Aes();

			// Encrypt
			cipherText = aes.encrypt(plainText);

			// Decrypt
			decryptedText = aes.decrypt(cipherText, keyToString(aes.getKey()));

			// Print
			System.out.println("AES-key in RAM\n--------------");
			System.out.println(aes.formatKeyText(aes));
			System.out.println("Encrypt - decrypt:");
			System.out.println(aes.formatPlainText(plainText));
			System.out.println(aes.formatCipherText(cipherText));
			System.out.println(aes.formatDecryptedText(decryptedText + "\n"));

			// ================================================== \\
			// Encryption/decryption with key from local storage \\
			// ================================================== \\

			// // SAVE SECRETKEY with settings in ./aes.xml
			// Create new key with the same settings.
			SecretKey key = generateKey(aes.getAlgorithm(), aes.getKeySize());
			// setKey() gives value to private key variable in aesLocal-object.
			aesLocal.setKey(key);
			keyConfig.put("Key", keyToString(aesLocal.getKey()));
			keyConfig.put("Algorithm", aesLocal.getAlgorithm());
			keyConfig.put("Iv", aesLocal.getIv());
			keyConfig.put("Transformation", aesLocal.getTransformation());
			File configFilePath = new File(getCurrentDirectory(), "aes_key.xml");
			saveConfiguration(configFilePath, keyConfig);

			// LOAD SECRETKEY with settings in ./aes.xml
			keyConfig1 = loadConfiguration(configFilePath); // File path
															// remained
															// identical.
			aesLocal.setKey(null); // Remove previously initialized AES key.
			aesLocal.setKey(stringToKey(keyConfig1.get("Key"), keyConfig1.get("Algorithm")));
			aesLocal.setIv(keyConfig1.get("Iv"));
			aesLocal.setTransformation(keyConfig1.get("Transformation"));

			// Encrypt
			cipherText = aesLocal.encrypt(plainText);

			// Decrypt
			decryptedText = aesLocal.decrypt(cipherText, keyToString(aes.getKey()));

			// Print
			System.out.println("AES-key from local storage:\n---------------------------");
			System.out.println(aes.formatKeyText(aesLocal));
			System.out.println("Encrypt - decrypt:");
			System.out.println(aesLocal.formatPlainText(plainText));
			System.out.println(aesLocal.formatCipherText(cipherText));
			System.out.println(aesLocal.formatDecryptedText(decryptedText));

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Initialization
	private SecretKey key = null;
	private String algorithm; // "AES
	private String transformation; // "AES/CBC/PKCS5Padding"
	private String password;
	private String salt;
	private String IV;
	private int iterations;
	private int keySize;

	// Constructor
	public Aes() throws NoSuchAlgorithmException {
		algorithm = "AES";
		transformation = Algorithm.AES_CBC_PKCS5PADDING.toString(); // "AES/CBC/PKCS5Padding";
		initSalt(16);
		initPassword(32);
		initIV();
		iterations = 3500;
		keySize = 256;
		generateKey();
	}

	// METHODS

	// Generate key
	public void generateKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		SecureRandom secureRandom = new SecureRandom();
		keyGenerator.init(keySize, secureRandom); // 128, 192 or 256
		this.key = generateKey(algorithm, keySize);
	}

	public static SecretKey generateKey(String algorithm, int keysize) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		SecureRandom secureRandom = new SecureRandom();
		keyGenerator.init(keysize, secureRandom); // 128, 192 or 256
		SecretKey key = keyGenerator.generateKey();
		return key;
	}

	// Old secret key method
	public SecretKey createSecretKey(KeySettings keySettings) throws NoSuchAlgorithmException, InvalidKeySpecException,
			InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchPaddingException, InvalidParameterSpecException {
		SecretKey secret;
		if (keySettings.getAlgorithm().equals("PBKDF2WithHmacSHA1") || keySettings.getAlgorithm().equals("PBKDF2WithHmacSHA512")) {
			SecretKeyFactory factory = SecretKeyFactory.getInstance(keySettings.getAlgorithm()); // //
																									// AES/CBC/PKCS5Padding.
																									// Options
																									// see
																									// http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory
			KeySpec spec = new PBEKeySpec( // password-based encryption
					keySettings.getPassword().toCharArray(), keySettings.getSalt().getBytes(), keySettings.getIterations(),
					keySettings.getKeySize());
			SecretKey tmp = factory.generateSecret(spec);
			secret = new SecretKeySpec(tmp.getEncoded(), keySettings.getAlgorithmName()); // getAlgorithmName()
																							// =
																							// "AES"
			return secret;
		} else {
			KeyGenerator kgen = KeyGenerator.getInstance(keySettings.getAlgorithmName());
			kgen.init(keySettings.getKeySize());
			SecretKey key = kgen.generateKey();
			SecretKeySpec skeySpec = new SecretKeySpec(key.getEncoded(), "AES");
			return skeySpec;
		}
	}

	/*
	 * Needs: Transformation: "AES/CBC/PKCS5Padding" Secret key
	 * 
	 * Returns: IV
	 */

	// Encrypt
	public byte[] encrypt(String plainText) throws Exception {
		Cipher cipher = Cipher.getInstance(transformation); // "AES/ECB/PKCS5Padding"
		byte[] keyBytes = key.getEncoded();
		SecretKeySpec key = new SecretKeySpec(keyBytes, algorithm); // "AES"
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));
		return cipher.doFinal(plainText.getBytes("UTF-8"));
	}

	// Decrypt
	public String decrypt(byte[] cipherText, String encryptionKey) throws Exception {
		Cipher cipher = Cipher.getInstance(transformation);
		byte[] keyBytes = key.getEncoded();
		SecretKeySpec key = new SecretKeySpec(keyBytes, algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
		return new String(cipher.doFinal(cipherText), "UTF-8");
	}

	public void initIV() {
		this.IV = RandomGenerator.getString(16);
	}

	public void initPassword(int bytes) {
		this.password = RandomGenerator.getString(32);
	}

	public void initSalt(int bytes) {
		this.salt = RandomGenerator.getString(bytes);
	}

	public SecretKey getKey() {
		return key;
	}

	public void setKey(SecretKey key) {
		this.key = key;
	}

	// Methods for printing
	private String formatKeyText(Aes aesKey) {
		String keySettings = "";
		try {
			keySettings += "Keysettings:\n";
			keySettings += String.format("%-16s%s\n", "Key: ", keyToString(aesKey.getKey()));
			keySettings += String.format("%-16s%s\n", "Algorithm: ", aesKey.getAlgorithm());
			keySettings += String.format("%-16s%s\n", "Transformation: ", aesKey.getTransformation());
			keySettings += String.format("%-16s%s\n", "IV: ", aesKey.getIv());
			return keySettings;
		} catch (IOException e) {
			e.printStackTrace();
			return String.format("%-16s%s", "Key: ", "Unable to convert key to String");
		}
	}

	private String formatCipherText(byte[] cipher) {
		return String.format("%-16s%s", "Encrypted: ", getString(cipher));
	}

	private String formatPlainText(String message) {
		return String.format("%-16s%s", "Plain: ", message);
	}

	private String formatDecryptedText(String message) {
		return String.format("%-16s%s", "Decrypted: ", message);
	}

	private String getString(byte[] cipher) {
		StringBuilder sb = new StringBuilder();
		for (byte i : cipher) {
			sb.append(i + " ");
		}
		return sb.toString();
	}

	public String getTransformation() {
		return transformation;
	}

	public void setTransformation(String transformation) {
		this.transformation = transformation;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getAlgorithm() {
		return algorithm.toString();
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	public String getIv() {
		return IV;
	}

	public void setIv(String iv) {
		this.IV = iv;
	}

	public int getIterations() {
		return iterations;
	}

	public void setIterations(int iterations) {
		this.iterations = iterations;
	}

	public int getKeySize() {
		return keySize;
	}

	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}
}

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