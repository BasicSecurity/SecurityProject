package be.pxl.encryption;

import java.security.SecureRandom;
import java.util.Random;

public class KeySettings {
	private String algorithmName;
	private Algorithm algorithm;	// for SecretKeyFactory.getInstance
	private String password;
	private String salt;
	private byte[] iv;
	private int iterations;
	private int keySize;
	
	public void initIv() {
		this.iv = RandomGenerator.getBytes(16);
	}
	
	public void initPassword(int bytes){
		this.password = RandomGenerator.getString(32);
	}
	
	public void initSalt(int bytes){
		this.salt = RandomGenerator.getString(bytes);
	}
		
	public String getAlgorithmName() {
		return algorithmName;
	}
	public void setAlgorithmName(String algorithmName) {
		this.algorithmName = algorithmName;
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
	public void setAlgorithm(Algorithm algorithm) {
		this.algorithm = algorithm;
	}
	public String getSalt() {
		return salt;
	}
	public void setSalt(String salt) {
		this.salt = salt;
	}
	public byte[] getIv() {
		return iv;
	}
	public void setIv(byte[] iv) {
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
