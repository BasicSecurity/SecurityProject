package be.pxl.encryption;

public enum Algorithm {
	
	AES_CBC_NOPADDING("AES/CBC/NoPadding"), 
	AES_CBC_PKCS5PADDING("AES/CBC/PKCS5Padding"),
	AES_ECB_NOPADDING("AES/ECB/NoPadding"), 
	AES_ECB_PKCS5PADDING("AES/ECB/PKCS5Padding"),
	PBKDF2WithHmacSHA512("PBKDF2WithHmacSHA512"),
	PBKDF2WithHmacSHA1("PBKDF2WithHmacSHA1");
	
	private String algorithm;
	
	Algorithm(String Algorithm){
		this.algorithm = Algorithm;
	}
	
	String get(){
		return algorithm;
	}
}
