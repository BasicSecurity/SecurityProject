package be.pxl.encryption;

public enum Algorithm {
	

	
	AES_CBC_NOPADDING{
		public String toString(){
			return "AES/CBC/NoPadding";
		}
	},
	AES_CBC_PKCS5PADDING{
		public String toString(){
			return "AES/CBC/PKCS5Padding";
		}
	},
	AES_ECB_NOPADDING{
		public String toString(){
			return "AES/ECB/NoPadding";
		}
	},
	AES_ECB_PKCS5PADDING{
		public String toString(){
			return "AES/ECB/PKCS5Padding";
		}
	},
	PBKDF2WithHmacSHA512("PBKDF2WithHmacSHA512"),
	PBKDF2WithHmacSHA1("PBKDF2WithHmacSHA1");
	
	private String algorithm;
	
	private Algorithm() {
		// TODO Auto-generated constructor stub
	}
	
	Algorithm(String Algorithm){
		this.algorithm = Algorithm;
	}
	
	String get(){
		return algorithm.toString();
	}
}
