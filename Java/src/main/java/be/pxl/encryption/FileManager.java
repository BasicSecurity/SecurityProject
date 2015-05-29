package be.pxl.encryption;

import static org.apache.commons.codec.binary.Hex.decodeHex;
import static org.apache.commons.codec.binary.Hex.encodeHex;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;

public class FileManager {
	
	public static String keyToString(SecretKey key) throws IOException {
		byte[] encoded = key.getEncoded();
		char[] hex = encodeHex(encoded);
		return String.valueOf(hex);
//		writeStringToFile(file, data);
	}
	
	public static SecretKey stringToKey(String hexString, String algorithm)
			throws IOException {
//		String data = new String(readFileToByteArray(file));
		char[] hex = hexString.toCharArray();
		byte[] encoded;
		try {
			encoded = decodeHex(hex);
		} catch (DecoderException e) {
			e.printStackTrace();
			return null;
		}
		SecretKey key = new SecretKeySpec(encoded, algorithm); // Algorithm = AES;
		return key;
	}

	public static void saveConfiguration(File configFile,
			TreeMap<String, String> keyConfig) throws IOException {
		try {
			Properties props = new Properties();
			for (Map.Entry<String, String> entry : keyConfig.entrySet()) {
				String key = entry.getKey();
				String value = entry.getValue();
				props.setProperty(key, value);
			}

			FileWriter writer = new FileWriter(configFile);
			OutputStream outputStream = new FileOutputStream(configFile);
			props.storeToXML(outputStream, "Encryption key settings file");
			writer.close();
		} catch (FileNotFoundException ex) {
			ex.printStackTrace();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}

	public static TreeMap<String, String> loadConfiguration(File file)
			throws IOException {
		TreeMap<String, String> keyConfig = new TreeMap<String, String>();
		try {
			FileInputStream  reader = new FileInputStream (file.getCanonicalPath());
		    Properties props = new Properties();
		    props.loadFromXML(reader);
		 
			keyConfig.put("Key", props.getProperty("Key"));
			keyConfig.put("Algorithm", props.getProperty("Algorithm"));
			keyConfig.put("Iv", props.getProperty("Iv"));
			keyConfig.put("Transformation", props.getProperty("Transformation"));
		
		    reader.close();
		    
		    return keyConfig;
		} catch (FileNotFoundException ex) {
			ex.printStackTrace();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public static String getCurrentDirectory() {
		try {
			return new File(".").getCanonicalPath();
		} catch (Exception e) {
			return null;
		}
		/*
		 * The current directory is /usr/local.
		 * File file = new File("../bin");
		 * System.out.println(file.getPath());
		 * System.out.println(file.getAbsolutePath());
		 * System.out.println(file.getCanonicalPath());
		 * would print:
		 * ../bin
		 * /usr/local/../bin
		 * /usr/bin
		 */
	}

}
