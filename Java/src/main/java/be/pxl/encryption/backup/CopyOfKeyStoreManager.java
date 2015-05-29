package be.pxl.encryption.backup;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import be.pxl.encryption.Aes;
import be.pxl.encryption.Algorithm;
import be.pxl.encryption.KeySettings;
import be.pxl.encryption.Message;
import be.pxl.encryption.Serializer;

public class CopyOfKeyStoreManager {

	private KeyStore keyStore;
	private String pathKeyStore;

	public CopyOfKeyStoreManager() {
		// I believe no exception will ever be thrown in this case.
		// That's why I removed the burden of try/catch for calling the default
		// constructor
		try {
			keyStore = KeyStore.getInstance("JCEKS"); // KeyStore.getDefaultType() would not store secret keys
		} catch (Exception e) {
			keyStore = null;
		}
	}

	public CopyOfKeyStoreManager(String keyStoreType) throws KeyStoreException {
		keyStore = KeyStore.getInstance(keyStoreType);
	}

	public void create(String pathKeyStore, String password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		File file = new File(pathKeyStore);
		file.mkdirs();
		keyStore.load(null, password.toCharArray());
		this.pathKeyStore = pathKeyStore;
	}

	public void open(String pathKey, String password) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(pathKey);
			keyStore.load(fis, password.toCharArray());
			pathKeyStore = new File(pathKey).getParent(); // get the directory
															// of the keystore
		} finally {
			if (fis != null) {
				fis.close();
			}
		}
	}

	public void write(String keyAlias, String password)
			throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {
		String keyPath = Paths.get(pathKeyStore, keyAlias).toString();
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(keyPath);
			keyStore.store(fos, password.toCharArray());
		} finally {
			if (fos != null) {
				fos.close();
			}
		}
	}

	public PrivateKey getPrivateKey(String privateKeyAlias, String password)
			throws NoSuchAlgorithmException, UnrecoverableEntryException,
			KeyStoreException {
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(
				password.toCharArray());
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore
				.getEntry(privateKeyAlias, protParam);
		PrivateKey myPrivateKey = pkEntry.getPrivateKey();
		return myPrivateKey;
	}

	public SecretKey getSecretKey(String secretKeyAlias, String password)
			throws NoSuchAlgorithmException, UnrecoverableEntryException,
			KeyStoreException {
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(
				password.toCharArray());
		KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry) keyStore
				.getEntry(secretKeyAlias, protParam);
		SecretKey mysecretKeyAlias = pkEntry.getSecretKey();
		return mysecretKeyAlias;
	}

	public void getTrustedCertificate() {

	}

	public void setPrivateKey() {

	}

	public void setSecretKey(String keyAlias, String password,
			SecretKey secretKey) throws KeyStoreException {
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(
				password.toCharArray());
		KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
		keyStore.setEntry(keyAlias, skEntry, protParam);
	}

	public void setTrustedCertificate() {

	}

	public static void main(String[] args) {
		CopyOfKeyStoreManager keyStore = new CopyOfKeyStoreManager();
		SecretKey aesKey;

		try {
			String text = "jos";
			String password = "jos";
			String pathKeyStore = Paths.get(System.getenv("appdata"),
					"\\BasicSecurity\\Keystore").toString();
			String keyAlias = "aes.key";
			keyStore.create(pathKeyStore, password);
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
			try {
				byte[] encryptedMessage = aes.encrypt(
						Serializer.serialize(text), secretKey, keySettings);
				message = new Message(keySettings.getIv(), encryptedMessage);
				byte[] decryptedMessage = aes.decrypt(message, secretKey,
						keySettings);
				System.out.printf("%-16s%s\n", "Plain text:", text);
				System.out.println(aes.printEncrypted(encryptedMessage));
				System.out.println(aes.printDecrypted(decryptedMessage) + "\n");
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			try{
			    KeyStore ks = KeyStore.getInstance("JCEKS");
			    ks.load(null, null);
			     
			    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			    keyGen.init(256);
			    Key key = keyGen.generateKey();
			     
			    ks.setKeyEntry("secret", key, "password".toCharArray(), null);
			     
			    ks.store(new FileOutputStream("output.jceks"), "password".toCharArray());
			} finally {
				
			}
			try{
			    KeyStore ks = KeyStore.getInstance("JCEKS");
			    ks.load(new FileInputStream("output.jceks"), "password".toCharArray());
			     
			    Key key = ks.getKey("secret", "password".toCharArray());
			    System.out.println(key.toString());
			    
			    byte[] encryptedMessage = aes.encrypt(
						Serializer.serialize(text), secretKey, keySettings);
				message = new Message(keySettings.getIv(), encryptedMessage);
			    byte[] decryptedMessage = aes.decrypt(message, secretKey,
						keySettings);
			    System.out.println(aes.printDecrypted(decryptedMessage) + "\n");
			} catch (Exception ex) {
			    ex.printStackTrace();
			}
			keyStore.setSecretKey(keyAlias, password, secretKey);
			aesKey = keyStore.getSecretKey(keyAlias, password);

		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		} catch (CertificateException e) {
			
			e.printStackTrace();
		} catch (IOException e) {
			
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			
			e.printStackTrace();
		} catch (KeyStoreException e) {
			
			e.printStackTrace();
		} catch (Exception ex) {
		    ex.printStackTrace();
		}

	}
}
