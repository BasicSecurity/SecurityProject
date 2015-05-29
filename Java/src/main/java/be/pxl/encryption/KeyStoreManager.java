package be.pxl.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import javax.crypto.SecretKey;

public class KeyStoreManager {

	private String keyStoreDir;

	public KeyStoreManager() {
		keyStoreDir = Paths.get(System.getenv("appdata"),
				"\\BasicSecurity\\Keystore").toString();
	}

	public KeyStoreManager(String keyStoreType) throws KeyStoreException {
		// keyStore = KeyStore.getInstance(keyStoreType);
	}

	public void storeKey(String keyAlias, Key userKey, char[] password,
			String keyStorePath) {
		KeyStore ks;
		try {
			ks = KeyStore.getInstance("JCEKS");
			
			File file = new File(keyStorePath);
			if (file.exists())
				ks.load(new FileInputStream(keyStorePath), password);
			else
				ks.load(null, null);

//			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//			keyGen.init(256);
//			Key key = keyGen.generateKey();

			ks.setKeyEntry(keyAlias, userKey, password, null);

			ks.store(new FileOutputStream(keyStorePath), password);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public Key loadKey(String keyStorePath, String keyAlias, char[] password) {
		try {
			KeyStore ks = KeyStore.getInstance("JCEKS");
			ks.load(new FileInputStream(keyStorePath), password);

			Key key = ks.getKey(keyAlias, password);
			System.out.println(key.toString());
			return key;
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}
	}

	public String getKeyStoreDir() {
		return keyStoreDir;
	}

	public void setKeyStoreDir(String keyStoreDir) {
		this.keyStoreDir = keyStoreDir;
	}

	public static void main(String[] args) {

		try {
			String text = "jos";
			String password = "jos";
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
			SecretKey secretKey = null;
			try {
				secretKey = aes.createSecretKey(keySettings);
			} catch (Exception e1) {
				e1.printStackTrace();
			}

			// BEGIN

			// /////////////////////////////////////////////////
			// /////////////////////////////////////////////////
			// /////////////////////////////////////////////////

			KeyStoreManager ksm = new KeyStoreManager();
			
			// C:\Users\<user>\AppData\Roaming\BasicSecurity\Keystore\KeyStore.jceks
			String keyStorePath = Paths.get(ksm.getKeyStoreDir(),
					"KeyStore.jceks").toString();
			ksm.storeKey("aes1.key", secretKey, password.toCharArray(),
					keyStorePath);
			ksm.storeKey("aes2.key", secretKey, password.toCharArray(),
					keyStorePath);
			Key key = ksm.loadKey(keyStorePath, "aes1.key",
					password.toCharArray());
			
			// ## Stopped working new AES class
//			try {
//				byte[] encryptedMessage = aes.encrypt(
//						Serializer.serialize(text), (SecretKey) key, keySettings);
//				message = new Message(keySettings.getIv(), encryptedMessage);
//				byte[] decryptedMessage = aes.decrypt(message,(SecretKey) key,
//						keySettings);
//				System.out.printf("%-16s%s\n", "Plain text:", text);
//				System.out.println(aes.printEncrypted(encryptedMessage));
//				System.out.println(aes.printDecrypted(decryptedMessage) + "\n");
//			} catch (Exception e) {
//				e.printStackTrace();
//			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
}
