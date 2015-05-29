package be.pxl.encryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class AdvancedCrypto {

//	public static final String PROVIDER = "BC";
	public static final int SALT_LENGTH = 20;
	public static final int IV_LENGTH = 16; // 16 bytes = 128 bits = AES block size
	public static final int PBE_ITERATION_COUNT = 3500;

	private static final String RANDOM_ALGORITHM = "SHA1PRNG";
	private static final String HASH_ALGORITHM = "SHA-512";
	private static final String PBE_ALGORITHM = "PBKDF2WithHmacSHA512";
	private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final String SECRET_KEY_ALGORITHM = "AES";
	
	private static final int KEY_LENGTH = 192;	//128, 192 or 256

	public String encrypt(SecretKey secret, String clearText)
			throws Exception {
		try {

			byte[] iv = generateIv();							// byte[16]
			String ivHex = Hex.encodeHexString(iv);				// 32 hex chars
			System.out.println("ivHex: " + ivHex);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			Cipher encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
			encryptionCipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
			byte[] encryptedText = encryptionCipher.doFinal(clearText
					.getBytes("UTF-8"));
			String encryptedHex = Hex.encodeHexString(encryptedText);

			return ivHex + encryptedHex;

		} catch (Exception e) {
			throw new Exception("Unable to encrypt", e);
		}
	}

	public String decrypt(SecretKey secret, String encrypted)
			throws Exception {
		try {
			Cipher decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
			String ivHex = encrypted.substring(0, IV_LENGTH * 2);
			String encryptedHex = encrypted.substring(IV_LENGTH * 2);
			IvParameterSpec ivspec = new IvParameterSpec(
					Hex.decodeHex(ivHex.toCharArray()));
			decryptionCipher.init(Cipher.DECRYPT_MODE, secret, ivspec);
			byte[] decryptedText = decryptionCipher.doFinal(Hex.decodeHex(encryptedHex.toCharArray()));
			String decrypted = new String(decryptedText, "UTF-8");
			return decrypted;
		} catch (Exception e) {
			throw new Exception("Unable to decrypt", e);
		}
	}

	public SecretKey getSecretKey(String password, String salt)
			throws Exception {
		try {
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(),
					Hex.decodeHex(salt.toCharArray()), PBE_ITERATION_COUNT, KEY_LENGTH);
			SecretKeyFactory factory = SecretKeyFactory.getInstance(
					PBE_ALGORITHM);
			SecretKey tmp = factory.generateSecret(pbeKeySpec);		// Create generic key.
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(),  // Create AES key.
					SECRET_KEY_ALGORITHM);
			return secret;
		} catch (Exception e) {
			throw new Exception("Unable to get secret key", e);
		}
	}

	public String getHash(String password, String salt) throws Exception {
		try {
			String input = password + salt;
			MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
			byte[] out = md.digest(input.getBytes("UTF-8"));
			return Hex.encodeHexString(out);
		} catch (Exception e) {
			throw new Exception("Unable to get hash", e);
		}
	}

	public String generateSalt() throws Exception {
		try {
			SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
			byte[] salt = new byte[SALT_LENGTH];
			random.nextBytes(salt);
			String saltHex = Hex.encodeHexString(salt);
			return saltHex;
		} catch (Exception e) {
			throw new Exception("Unable to generate salt", e);
		}
	}

	private byte[] generateIv() throws NoSuchAlgorithmException,
			NoSuchProviderException {
		SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
		byte[] iv = new byte[IV_LENGTH];
		random.nextBytes(iv);
		return iv;
	}
	
//	public String encryptObject(SecretKey secret, String clearText)
//			throws Exception {
//		try {
//
//			byte[] iv = generateIv();
//			String ivHex = Hex.encodeHexString(iv);
//			System.out.println("ivHex: " + ivHex);
//			IvParameterSpec ivspec = new IvParameterSpec(iv);
//
//			Cipher encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
//			encryptionCipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
//			byte[] encryptedText = encryptionCipher.doFinal(clearText
//					.getBytes("UTF-8"));
//			String encryptedHex = Hex.encodeHexString(encryptedText);
//
//			return ivHex + encryptedHex;
//
//		} catch (Exception e) {
//			throw new Exception("Unable to encrypt", e);
//		}
//	}
//
//	public String decryptObject(SecretKey secret, Object encrypted)
//			throws Exception {
//		try {
//			Cipher decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
//			String ivHex = encrypted.substring(0, IV_LENGTH * 2);
//			String encryptedHex = encrypted.substring(IV_LENGTH * 2);
//			IvParameterSpec ivspec = new IvParameterSpec(
//					Hex.decodeHex(ivHex.toCharArray()));
//			decryptionCipher.init(Cipher.DECRYPT_MODE, secret, ivspec);
//			byte[] decryptedText = decryptionCipher.doFinal(Hex.decodeHex(encryptedHex.toCharArray()));
//			String decrypted = new String(decryptedText, "UTF-8");
//			return decrypted;
//		} catch (Exception e) {
//			throw new Exception("Unable to decrypt", e);
//		}
//	}
}
