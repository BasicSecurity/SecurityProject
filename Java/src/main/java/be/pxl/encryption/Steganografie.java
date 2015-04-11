package be.pxl.encryption;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;

public class Steganografie {

	private BufferedImage img;
	private String message;

	public Steganografie(String message) {
		try {
			img = ImageIO.read(new File("praisethelord.png"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		this.message = message;

	}

	public Steganografie(File file, String message) {
		try {
			// img = ImageIO.read(file);
			img = ImageIO.read(new File("praisethelord.png"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		this.message = message;
	}

	public void encrypt() {
		// Initial variables
		int width = img.getWidth();
		int height = img.getHeight();
		int pixels = width * height;
		int numberOfLetters = 3 * pixels / 8;
		int messageSize = message.length()*8;
	

		// Calculate the amount of bits needed
		String numberOfLettersBinary = Integer.toString(numberOfLetters, 2);
		int numberOfLettersBinarySize = numberOfLettersBinary.length();
		while (numberOfLettersBinarySize % 3 != 0) {
			numberOfLettersBinarySize += 1;
		}

		// Ultimate Variables
		int numberOfLettersPixels = numberOfLettersBinarySize/3;
		int pixelsForMessage = pixels - numberOfLettersPixels;

		// Check message size
		if (message.length() * 8 > pixelsForMessage)
			System.out.println("Image too small or text message too big");
		else
			System.out.println("Message and image compatible");	
		
		
		// Messagesize binair in de eerste zoveel pixels stoppen
		String messageSizeBinaryString = Integer.toString(messageSize, 2);
		String messageBinaryLength = Integer.toString(message.length(),2);
//		
//		for(int i=0;i<numberOfLettersPixels;i++){
//			int rgb = img.getRGB(i, 0);
//			
//			int alpha = (rgb & 0xFF000000) >>> 24;
//			int red = (rgb & 0x00FF0000) >>> 16;
//			int green = (rgb & 0x0000FF00) >>> 8;
//			int blue = (rgb & 0x000000FF) >>> 0;

			
//			for(int j=0;j<3;j++){
//				//Generate new rgb int
//				
//				
//				
//			}
			
			
//			//Generate new rgb int
//			messageBinaryLength
//			
//			//implement new rgb			
//			img.setRGB(i, 0, arg2);
//		} 
//		img.setRGB(arg0, arg1, arg2);

	}

	public void decrypt() {

	}

}
