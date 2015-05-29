package be.pxl.encryption;

import java.security.SecureRandom;

public class RandomGenerator {

	public static byte[] getBytes(int numberOfBytes) {
		SecureRandom rand = new SecureRandom();
		byte[] iv = new byte[numberOfBytes];
		rand.nextBytes(iv);
		return iv;
	}
	
	public static String getString(int numberOfCharacters) {
		StringBuilder password = new StringBuilder();
		String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW0123456789";
		SecureRandom rand = new SecureRandom();
		int index;
		for (int i = 0 ; i < numberOfCharacters; i++){
			index = rand.nextInt(chars.length() - 1);
			password.append(chars.substring(index, index + 1));
		}
		return password.toString();
	}
	
//	// Wrong amount of bytes after getBytes("UTF-8") with the method below.
//	public static String getString(int numberOfCharacters) {
//		StringBuilder password = new StringBuilder();
//		String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/*-+?./%µ()[]{}";
//		SecureRandom rand = new SecureRandom();
//		int index;
//		for (int i = 0 ; i < numberOfCharacters; i++){
//			index = rand.nextInt(chars.length() - 1);
//			password.append(chars.substring(index, index + 1));
//		}
//		return password.toString();
//	}
}
