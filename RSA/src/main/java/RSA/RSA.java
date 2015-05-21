package RSA;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import javax.crypto.Cipher;

public class RSA {

  public static final String ALGORITHM = "RSA"; // De methode van het algorithme
  public static final String PRIVATE_KEY_FILE = "private.key"; // Waar de private key wordt bijgehouden
  public static final String PUBLIC_KEY_FILE = "public.key"; // Waar de public key wordt bijgehouden
  
  @SuppressWarnings("resource")
	public static void main(String[] args) {
	
	    try {
	
	      if (!areKeysPresent()) {
	        generateKey();
	      }
	
	      	//final String originalText = "Text"; // Uncomment voor handmatig toevoegen
			System.out.println("Geef de sleutel in:"); // Comment voor handmatig toevoegen
			Scanner input = new Scanner(System.in); // Comment voor handmatig toevoegen
			final String originalText = input.nextLine(); // Comment voor handmatig toevoegen
			input.close(); // Comment voor handmatig toevoegen
			
	      ObjectInputStream inputStream = null;
	
	      inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE)); // Encrypteer met de public key
	      final PublicKey publicKey = (PublicKey) inputStream.readObject();
	      final byte[] cipherText = encrypt(originalText, publicKey);
	
	      inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE)); // Decrypteer met de private key
	      final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
	      final String plainText = decrypt(cipherText, privateKey);
	
	      // Printen in console
	      //System.out.println("Original: " + originalText);
	      //System.out.println("Encrypted: " +cipherText.toString());
	      //System.out.println("Decrypted: " + plainText);
	
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	  }
  
	  public static void generateKey() {
	    try {
	      final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM); // Maak een nieuw object aan van het type KeyPairGenerator
	      keyGen.initialize(1024);
	      final KeyPair key = keyGen.generateKeyPair(); // Ingebouwde functie die opgeroepen wordt om de keypair te genereren
	
	      File privateKeyFile = new File(PRIVATE_KEY_FILE); // Maak een nieuwe file object voor beide keys
	      File publicKeyFile = new File(PUBLIC_KEY_FILE);
	
	      if (privateKeyFile.getParentFile() != null) { // Als de map niet bestaat maak deze aan
	        privateKeyFile.getParentFile().mkdirs();
	      }
	      privateKeyFile.createNewFile(); // Maak een leeg bestand aan, private.key
	
	      if (publicKeyFile.getParentFile() != null) {
	        publicKeyFile.getParentFile().mkdirs();
	      }
	      publicKeyFile.createNewFile(); // Maak een leeg bestand aan, public.key
	
	      // Public key opslaan
	      ObjectOutputStream publicKeyOS = new ObjectOutputStream(
	          new FileOutputStream(publicKeyFile));
	      publicKeyOS.writeObject(key.getPublic());
	      publicKeyOS.close();
	
	      // Private key opslaan
	      ObjectOutputStream privateKeyOS = new ObjectOutputStream(
	          new FileOutputStream(privateKeyFile));
	      privateKeyOS.writeObject(key.getPrivate());
	      privateKeyOS.close();
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	
	  }

	  public static boolean areKeysPresent() {
	
	    File privateKey = new File(PRIVATE_KEY_FILE);
	    File publicKey = new File(PUBLIC_KEY_FILE);
	
	    if (privateKey.exists() && publicKey.exists()) {
	      return true;
	    }
	    return false;
	  }

	  public static byte[] encrypt(String text, PublicKey key) {
	    byte[] cipherText = null;
	    try {
	      final Cipher cipher = Cipher.getInstance(ALGORITHM); // Algorithm = RSA
	      cipher.init(Cipher.ENCRYPT_MODE, key); // Enrypteer met de public key
	      cipherText = cipher.doFinal(text.getBytes());
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	    return cipherText;
	  }

	  public static String decrypt(byte[] text, PrivateKey key) {
	    byte[] dectyptedText = null;
	    try {
	      final Cipher cipher = Cipher.getInstance(ALGORITHM); // Algorithm = RSA
	
	      cipher.init(Cipher.DECRYPT_MODE, key); // Decrypteer met de private key
	      dectyptedText = cipher.doFinal(text);
	
	    } catch (Exception ex) {
	      ex.printStackTrace();
	    }
	
	    return new String(dectyptedText);
	  }
}