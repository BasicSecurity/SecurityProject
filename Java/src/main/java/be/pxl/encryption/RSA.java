package be.pxl.encryption;
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
	
	      // Saving the Public key in a file
	      ObjectOutputStream publicKeyOS = new ObjectOutputStream(
	          new FileOutputStream(publicKeyFile));
	      publicKeyOS.writeObject(key.getPublic());
	      publicKeyOS.close();
	
	      // Saving the Private key in a file
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
	      // get an RSA cipher object and print the provider
	      final Cipher cipher = Cipher.getInstance(ALGORITHM);
	      // encrypt the plain text using the public key
	      cipher.init(Cipher.ENCRYPT_MODE, key);
	      cipherText = cipher.doFinal(text.getBytes());
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	    return cipherText;
	  }

	  public static String decrypt(byte[] text, PrivateKey key) {
	    byte[] dectyptedText = null;
	    try {
	      // get an RSA cipher object and print the provider
	      final Cipher cipher = Cipher.getInstance(ALGORITHM);
	
	      // decrypt the text using the private key
	      cipher.init(Cipher.DECRYPT_MODE, key);
	      dectyptedText = cipher.doFinal(text);
	
	    } catch (Exception ex) {
	      ex.printStackTrace();
	    }
	
	    return new String(dectyptedText);
	  }

  	@SuppressWarnings("resource")
	public static void main(String[] args) {
	
	    try {
	
	      // Check if the pair of keys are present else generate those.
	      if (!areKeysPresent()) {
	        // Method generates a pair of keys using the RSA algorithm and stores it
	        // in their respective files
	        generateKey();
	      }
	
	      //final String originalText = "Text to be encrypted ";
			System.out.println("Geef de sleutel in:");
			Scanner input = new Scanner(System.in);
			final String originalText = input.nextLine();
			input.close();
			
	      ObjectInputStream inputStream = null;
	
	      // Encrypt the string using the public key
	      inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
	      final PublicKey publicKey = (PublicKey) inputStream.readObject();
	      final byte[] cipherText = encrypt(originalText, publicKey);
	
	      // Decrypt the cipher text using the private key.
	      inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
	      final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
	      final String plainText = decrypt(cipherText, privateKey);
	
	      // Printing the Original, Encrypted and Decrypted Text
	      System.out.println("Original: " + originalText);
	      System.out.println("Encrypted: " +cipherText.toString());
	      System.out.println("Decrypted: " + plainText);
	
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	  }
}