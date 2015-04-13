package be.pxl.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class KeyStoreManager {

	private KeyStore keyStore;
	private String pathKeyStore;

	public KeyStoreManager() {
		// I believe no exception will ever be thrown in this case.
		// That's why I removed the burden of try/catch for calling the default
		// constructor
		try {
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (Exception e) {
			keyStore = null;
		}
	}

	public KeyStoreManager(String keyStoreType) throws KeyStoreException {
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
		KeyStoreManager keyStore = new KeyStoreManager();
		try {
			String password = "jos";
			String pathKeyStore = Paths.get(System.getenv("appdata"),
					"\\BasicSecurity\\Keystore").toString();
			String keyAlias = "aes.key";
			keyStore.create(pathKeyStore, password);

			Aes aes = new Aes();
			aes.getKeySettings().setAlgorithm(Algorithm.PBKDF2WithHmacSHA512);
			aes.getKeySettings()
					.setPassword("0123456789abcdef0123456789abcdef");
			aes.getKeySettings().setSalt("imma salt!");
			aes.getKeySettings().setKeySize(256);
			aes.getKeySettings().setIterations(65536);
			aes.getKeySettings().setIv("AAAAAAAA");

			SecretKey aesKey = aes.createSecretKey();

			keyStore.create(pathKeyStore, password);
			keyStore.write(keyAlias, password);
			aesKey = null;
			aesKey = keyStore.getSecretKey(keyAlias, password);
			
			aes.encrypt("Jos is een pornovos in het bos", aesKey);

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
