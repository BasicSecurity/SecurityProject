package be.pxl.encryption;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;

public class Gui extends JFrame {
	private JPanel eastPanel, centerPanel, westPanel, buttonPanel, textPanel, blanco1, blanco2, blanco3;
	private JButton decryptButton, encryptButton;
	private JTextField encryptedTextArea, decryptedTextArea;
//	private JTextArea encryptedTextArea, decryptedTextArea;
//	private ArrayList<JComponent> components;

	public Gui() {
		super("Ubercrypt");
		eastPanel = new JPanel();
		centerPanel = new JPanel();
		westPanel = new JPanel();
		buttonPanel = new JPanel();
		textPanel = new JPanel();
		blanco1 = new JPanel();
		blanco2 = new JPanel();
		blanco3 = new JPanel();
		decryptButton = new JButton("Decrypt");
		decryptButton.setSize(30,20);
		encryptButton = new JButton("Encrypt");
		encryptButton.setSize(30,20);
		encryptedTextArea = new JTextField(10);
		decryptedTextArea = new JTextField(10);

		setLayout(new BorderLayout());
		add(westPanel, BorderLayout.WEST);
		add(centerPanel, BorderLayout.CENTER);
		add(eastPanel, BorderLayout.EAST);
		
		westPanel.setLayout(new BorderLayout());
		westPanel.add(buttonPanel, BorderLayout.NORTH);
		westPanel.add(blanco1, BorderLayout.CENTER);
		buttonPanel.setLayout(new GridLayout(2, 1));
		buttonPanel.add(encryptButton);
		buttonPanel.add(decryptButton);
		
		centerPanel.setLayout(new BorderLayout());
		centerPanel.add(textPanel, BorderLayout.NORTH);
		centerPanel.add(blanco2, BorderLayout.CENTER);
		textPanel.setLayout(new GridLayout(2, 1));
		textPanel.add(encryptedTextArea);
		textPanel.add(decryptedTextArea);
		
		westPanel.setLayout(new BorderLayout());
		westPanel.add(blanco3);
		

		
//		westPanel.setLayout(new BorderLayout());
//		westPanel.add(buttonPanel, BorderLayout.NORTH);
//		westPanel.add(blanco1, BorderLayout.CENTER);
//		buttonPanel.setLayout(new GridLayout(2, 1));
//		buttonPanel.add(encryptButton);
//		buttonPanel.add(decryptButton);
//		eastPanel.setLayout(new BorderLayout());
//		eastPanel.add(textPanel, BorderLayout.NORTH);
//		eastPanel.add(blanco2, BorderLayout.CENTER);
//		textPanel.setLayout(new GridLayout(2, 1));
//		textPanel.add(encryptedTextArea);
//		textPanel.add(decryptedTextArea);
		
		setSize(new Dimension(500, 200));
		setVisible(true);
		setDefaultCloseOperation(EXIT_ON_CLOSE);
	}

	public static void main(String[] args) {
//		Gui gui = new Gui();
	}
}
