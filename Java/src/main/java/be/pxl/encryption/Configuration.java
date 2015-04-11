package be.pxl.encryption;

import javax.crypto.SecretKeyFactory;

public class Configuration {
	private Algorithm algorithm;	// for SecretKeyFactory.getInstance
	private String password;
	private String salt;
	private String iv;
	private int iterations;
	private int keySize;
	
	
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public Algorithm getAlgorithm() {
		return algorithm;
	}
	public void setAlgorithm(Algorithm algorithm) {
		this.algorithm = algorithm;
	}
	public String getSalt() {
		return salt;
	}
	public void setSalt(String salt) {
		this.salt = salt;
	}
	public String getIv() {
		return iv;
	}
	public void setIv(String iv) {
		this.iv = iv;
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
