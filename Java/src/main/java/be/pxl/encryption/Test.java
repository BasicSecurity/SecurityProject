package be.pxl.encryption;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;

public class Test {
	private static BufferedImage img;

	public static void main(String[] args) {

		try {
			img = ImageIO.read(new File("output.png"));
		} catch (IOException e) {
			e.printStackTrace();
		}

		String messageSizeBinaryString = "00000000000101001000";

		for (int i = 0; i < 5; i++) {
			System.out.println("Loop: " + i);
			int rgb = img.getRGB(i, 0);
			String rgbString = "";
			int operation;
			for (int j = 24; j >= 0; j -= 8) {
				if (j == 24)
					operation = 0xFF000000;
				else if (j == 16)
					operation = 0x00FF0000;
				else if (j == 8)
					operation = 0x0000FF00;
				else
					operation = 0x000000FF;
				
				int channel = (rgb & operation) >>> j;
				String channelString = formatToBinaryString(channel);
				rgbString = rgbString
						+ channelString.substring(0, 7)
						+ messageSizeBinaryString.substring((4 * i),
								(4 * i) + 1);
				System.out.println(rgbString);
			}
			Integer newRgbValue = Integer.parseUnsignedInt(rgbString, 2);
			System.out.println("Value: " + newRgbValue);
		}

	}

	public static String formatToBinaryString(int decimal) {
		String binaryString = Integer.toString(decimal, 2);
		while (binaryString.length() != 8) {
			binaryString = "0" + binaryString;
		}
		return binaryString;
	}

}



/*Backup Encryption

for(int i=0;i<headerPixels;i++){
int rgb = image.getRGB(i, 0);			

int alpha = (rgb & 0xFF000000) >>> 24;
String alphaString = formatToBinaryString(alpha);			
alphaString = alphaString.substring(0,7) + messageSizeBinaryString.substring((4*i),(4*i)+1);			
System.out.println(alphaString);


int red = (rgb & 0x00FF0000) >>> 16;
String redString = formatToBinaryString(red);				
redString = redString.substring(0,7) + messageSizeBinaryString.substring(4*i+1,4*i+2);			
System.out.println(redString);		


int green = (rgb & 0x0000FF00) >>> 8;
String greenString = formatToBinaryString(green);	
greenString = greenString.substring(0,7) + messageSizeBinaryString.substring(4*i+2,4*i+3);			
System.out.println(greenString);		


int blue = (rgb & 0x000000FF) >>> 0;
String blueString = formatToBinaryString(blue);				
blueString = blueString.substring(0,7) + messageSizeBinaryString.substring(4*i+3,4*i+4);			
System.out.println(blueString);		


String rgbString = alphaString + redString + greenString + blueString;
System.out.println("Resulting rgb value (binair): " + rgbString);
Integer newRgbValue = Integer.parseUnsignedInt(rgbString,2);
System.out.println("Value " + i + ": "  + newRgbValue);
System.out.println("Placed at pixel: " + i);			

image.setRGB(i, 0, newRgbValue);			
} 	*/