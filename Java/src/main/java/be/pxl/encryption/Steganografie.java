package be.pxl.encryption;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;

public class Steganografie {

	private int width, height, headerPixels, messagePixels;

	private BufferedImage img, image;
	private File outputfile;

	public Steganografie(File file) {
		try {
			img = ImageIO.read(file);
			outputfile = new File("output.png");
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Nieuwe bufferedImage met juiste type aanmaken en orginele afbeelding kopieren.
		image = new BufferedImage(img.getWidth(), img.getHeight(), 2);
		for (int i = 0; i < img.getWidth(); i++)
			for (int j = 0; j < img.getHeight(); j++) {
				image.setRGB(i, j, img.getRGB(i, j));
			}
	}

	// De grootte van de header wordt bepaald door de resolutie en moet bij elke afbeelding berekend worden.
	public void calculateHeader() {

		// Initial variables
		width = image.getWidth();
		height = image.getHeight();
		int pixels = width * height;
		int maximumNumberOfLetters = pixels / 2; // maximaal aantal tekens in afbeelding

		String maximumNumberOfLettersBinary = Integer.toString(
				maximumNumberOfLetters, 2);
		int maximumNumberOfLettersBinarySize = maximumNumberOfLettersBinary
				.length();
		while (maximumNumberOfLettersBinarySize % 4 != 0) { // aantal bits moet een veelvoud van 4 zijn (4bits/pixel)
			maximumNumberOfLettersBinarySize += 1;
		}

		// Ultimate Variables
		headerPixels = maximumNumberOfLettersBinarySize / 4; // Aantal pixels nodig voor header
		messagePixels = pixels - headerPixels; // Aantal pixels over voor bericht.
	}

	// Deze methode zorgt ervoor dat een binair getal altijd 8 bits heeft.
	public String formatToBinaryString(int decimal) {
		String binaryString = Integer.toString(decimal, 2);
		System.out.println("BinaryString = " + binaryString);
		System.out.println("Length: " + binaryString.length());
		while (binaryString.length() != 8) {
			binaryString = "0" + binaryString;
			System.out.println("string adjusted");
		}
		return binaryString;
	}

	public void encrypt(String message) {

		calculateHeader();

		int messageSize = message.length() * 2; // Pixels

		// Check message size
		if (messageSize > messagePixels)
			System.out.println("Image too small or text message too big");
		else
			System.out.println("Message and image compatible");
		System.out.println("Pixels for header: " + headerPixels);
		System.out.println("Pixels for message: " + messagePixels);
		System.out
				.println("Maximum number of characters: " + messagePixels / 2);
		System.out.println("Aantal tekens bericht: " + message.length());
		System.out.println("Aantal pixels nodig: " + messageSize);

		System.out.println("");

		// Messagesize binair in de eerste zoveel pixels stoppen
		String messageSizeBinaryString = Integer.toString(messageSize, 2); // aantal pixels binair uitgeschreven
		System.out.println("Aantal pixels nodig (binair): "
				+ messageSizeBinaryString);

		// Zorgen voor het juiste format
		while (messageSizeBinaryString.length() != headerPixels * 4) {
			messageSizeBinaryString = "0" + messageSizeBinaryString;
		}

		System.out.println("Juiste format: " + messageSizeBinaryString);

		int operation;
		String rgbString;
		int counter = 0;

		for (int i = 0; i < headerPixels; i++) {
			int rgb = image.getRGB(i, 0);
			rgbString = "";
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
				rgbString = rgbString + channelString.substring(0, 7)
						+ messageSizeBinaryString.substring(counter, ++counter);
				System.out.println(rgbString);
			}
			System.out.println("Placed at pixel: " + i);
			Integer newRgbValue = Integer.parseUnsignedInt(rgbString, 2);
			System.out.println("Value " + i + ": " + newRgbValue);
			image.setRGB(i, 0, newRgbValue);
		}

		System.out.println("\nHeader created");
		System.out.println("\nMessage in binary code: ");

		byte[] messageBytes = message.getBytes();
		String messageArray[] = new String[message.length()];

		// Bericht in array van strings omzetten
		for (int i = 0; i < messageBytes.length; i++) {
			Byte bytes = new Byte(messageBytes[i]);
			messageArray[i] = Integer.toString(bytes.intValue(), 2);
			while(messageArray[i].length()!=8){
				messageArray[i] = "0" + messageArray[i];				
			}
			System.out.println(messageArray[i]);
		}

		System.out.println("\nimplementing message");
		int i = 0;
		for (int j = 0; j < messageArray.length; j++) {
			for (int k = 0; k < 2; k++) {
				System.out.println("character: " + j);

				int rgb = image.getRGB(j + headerPixels, 0);

				int alpha = (rgb & 0xFF000000) >>> 24;
				String alphaString = formatToBinaryString(alpha);
				alphaString = alphaString.substring(0, 7)
						+ messageArray[j].substring((4 * k), (4 * k) + 1);
				System.out.println(alphaString);

				int red = (rgb & 0x00FF0000) >>> 16;
				String redString = formatToBinaryString(red);
				redString = redString.substring(0, 7)
						+ messageArray[j].substring(4 * k + 1, 4 * k + 2);
				System.out.println(redString);

				int green = (rgb & 0x0000FF00) >>> 8;
				String greenString = formatToBinaryString(green);
				greenString = greenString.substring(0, 7)
						+ messageArray[j].substring(4 * k + 2, 4 * k + 3);
				System.out.println(greenString);

				int blue = (rgb & 0x000000FF) >>> 0;
				String blueString = formatToBinaryString(blue);
				blueString = blueString.substring(0, 7)
						+ messageArray[j].substring(4 * k + 3, 4 * k + 4);
				System.out.println(blueString);

				String rgbString1 = alphaString + redString + greenString
						+ blueString;
				Integer newRgbValue = Integer.parseUnsignedInt(rgbString1, 2);
				System.out.println("Value " + j + ": " + newRgbValue);

				image.setRGB(i + headerPixels, 0, newRgbValue);
				System.out.println("Placed at pixel: " + (i + headerPixels) + "\n");
				// System.out.println(image.getRGB(j + headerPixels, 0));

				i++;

			}
		}

		try {
			ImageIO.write(image, "png", outputfile);
			System.out.println("Write succesfull");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public void decrypt() {
		try {
			img = ImageIO.read(outputfile);
			System.out.println("type: " + img.getType());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("DECRYPT \n\n\n\n");

		// Decrypt header
		int header = headerPixels;
		System.out.println(header);

		String headerString = "";

		for (int i = 0; i < header; i++) {
			int rgb = img.getRGB(i, 0);

			int alpha = (rgb & 0xFF000000) >>> 24;
			String alphaString = formatToBinaryString(alpha);
			System.out.println(alphaString);
			headerString = headerString + alphaString.substring(7, 8);

			int red = (rgb & 0x00FF0000) >>> 16;
			String redString = formatToBinaryString(red);
			System.out.println(redString);
			headerString = headerString + redString.substring(7, 8);

			int green = (rgb & 0x0000FF00) >>> 8;
			String greenString = formatToBinaryString(green);
			System.out.println(greenString);
			headerString = headerString + greenString.substring(7, 8);

			int blue = (rgb & 0x000000FF) >>> 0;
			String blueString = formatToBinaryString(blue);
			System.out.println(blueString);
			headerString = headerString + blueString.substring(7, 8);

			System.out.println();

		}

		// Decrypt message

		int numberOfCharacters = Integer.parseInt(headerString, 2);
		System.out.println("Number of pixels to read: " + numberOfCharacters);

		String[] messageString = new String[numberOfCharacters / 2];
		String messagePart = "";

		int k = 0;
		int l = 0;

		for (int i = header; i < header + numberOfCharacters / 2; i++) {
			for (int j = 0; j < 2; j++) {
				System.out.println("reading pixel: " + (l + header));
				int rgb = img.getRGB(l + header, 0);

				int alpha = (rgb & 0xFF000000) >>> 24;
				String alphaString = formatToBinaryString(alpha);

				System.out.println(alphaString);
				messagePart = messagePart + alphaString.substring(7, 8);

				int red = (rgb & 0x00FF0000) >>> 16;
				String redString = formatToBinaryString(red);
				System.out.println(redString);
				messagePart = messagePart + redString.substring(7, 8);

				int green = (rgb & 0x0000FF00) >>> 8;
				String greenString = formatToBinaryString(green);
				System.out.println(greenString);
				messagePart = messagePart + greenString.substring(7, 8);

				int blue = (rgb & 0x000000FF) >>> 0;
				String blueString = formatToBinaryString(blue);
				System.out.println(blueString);
				messagePart = messagePart + blueString.substring(7, 8);
				l++;

			}
			messageString[k] = messagePart;
			System.out.println("Messagepart " + k + ": " + messagePart);
			messagePart = "";
			k++;

		}
		System.out.print("Message: ");
		for (int i = 0; i < messageString.length; i++) {
			System.out.print((char) Integer.parseInt(messageString[i], 2));
		}

	}

	public static void main(String[] args) {
		Steganografie stegano = new Steganografie(new File("praisethelord.png"));
		stegano.encrypt("Vrijdag 12u30 schoolpoort. Kom alleen");
		stegano.decrypt();

	}

}
