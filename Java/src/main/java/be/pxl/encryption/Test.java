package be.pxl.encryption;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;

public class Test {
	
		
	public static void main(String[] args) {
		BufferedImage img = null;
		try {
			img = ImageIO.read(new File("praisethelord.png"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(img.getRGB(0,0));
		System.out.println(Integer.toString(img.getRGB(0,0)));
		
		//int test = 
		
		//img.setRGB(0, 0,);
		
		
	}

}
