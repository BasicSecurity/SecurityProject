package be.pxl.encryption;

import java.util.Arrays;

public class Message {
	private byte[] iv;
	private byte[] message;
	
	public Message() {}

	public Message(byte[] iv, byte[] message) {
		this.iv = iv;
		this.message = message;
	}

	public byte[] getIv() {
		return iv;
	}
	public void setIv(byte[] iv) {
		this.iv = iv;
	}
	public byte[] getMessage() {
		return message;
	}
	public void setMessage(byte[] message) {
		this.message = message;
	}
	
	public static Message split(byte[] messageWithIv){
		Message message = new Message();
		message.setIv(Arrays.copyOfRange(messageWithIv, 0, 15));
		message.setMessage(Arrays.copyOfRange(messageWithIv, 16, messageWithIv.length - 16));
		return message;
	}
}
