package eu.giuseppeurso.security.jca.crypto;

import java.io.File;
import java.util.Arrays;
import java.util.Random;

import org.apache.commons.io.FileUtils;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for PasswordBasedEncryption.
 * 
 * @author Giuseppe Urso
 * 
 */
public class PasswordBasedEncryptionTest extends TestCase {

	private String resourceDir = "";
	private String targetDir = "";
	private String fileToEncrypt = "";
	private String fileToDecrypt01 = "";
	private String fileToDecrypt02 = "";
	private String password = "";
	
	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite() {
		return new TestSuite(PasswordBasedEncryptionTest.class);
	}
	
	/**
	 * Setup test cases
	 */
	public void setUp() {
		resourceDir = "src/test/resources";
		targetDir = "target";
		fileToEncrypt = resourceDir + "/clear-text.txt";
		fileToDecrypt01 = resourceDir + "/pbe-fixedsalt-encryption.bin";
		fileToDecrypt02 = resourceDir + "/pbe-randomsalt-encryption.bin";
		password = "12345";
	}   

	/**
	 * Test case for the encryption with constant salt
	 * 
	 * @throws Exception
	 */
	public void testEncrypt() throws Exception {

		boolean actual = false;
		File file = new File(fileToEncrypt);
		byte[] plaintext = FileUtils.readFileToByteArray(file);
		byte[] cipherText = PasswordBasedEncryption.encrypt(plaintext, password);
		String cipherTextValue = new String(cipherText, "UTF-8");
		if (cipherText.length>0 && !cipherTextValue.contains("clear text!!!!")) {
    		actual = true;
		}
    	assertEquals("Invalid encryption.", true, actual);
    	Random rand = new Random();
		int randomId = rand.nextInt(90000000); 
    	file = new File(targetDir+"/fixedsalt-encryption-"+randomId+".bin");
    	FileUtils.writeByteArrayToFile(file, cipherText);
		
	}

	 /** Test case for the decryption with constant salt
	 * 
	 * @throws Exception
	 */
	public void testDecrypt() throws Exception {

		boolean actual = false;
		File file = new File(fileToEncrypt);
		byte[] plaintext = FileUtils.readFileToByteArray(file);
		file = new File(fileToDecrypt01);
		byte[] cipherText = FileUtils.readFileToByteArray(file);
		byte[] decryptedText = PasswordBasedEncryption.decrypt(cipherText, password);
		
		String originalTextValue = new String(plaintext, "UTF-8");
		String decryptedTextValue = new String(decryptedText, "UTF-8");
		System.out.println("Original text was: "+ originalTextValue);
		System.out.println("Decrypted text is: "+decryptedTextValue);
		if (Arrays.equals(plaintext, decryptedText)) {
    		actual = true;
		}
    	assertEquals("Invalid decryption.", true, actual);
	}
	
	/**
	 * Test case for encryption with random salt
	 * @throws Exception
	 */
	public void testEncryptWithRandomSalt() throws Exception {
		boolean actual = false;
		Random rand = new Random();
		int randomId = rand.nextInt(90000000); 
    	String outFile = targetDir+"/randomsalt-encryption-"+randomId+".bin";
		PasswordBasedEncryption.encryptWithRandomSalt(fileToEncrypt, outFile, password);
		File file = new File(outFile);
		byte[] cipherText = FileUtils.readFileToByteArray(file);
		String cipherTextValue = new String(cipherText, "UTF-8");
		if (cipherText.length>0 && !cipherTextValue.contains("clear text!!!!")) {
    		actual = true;
		}
    	assertEquals("Invalid encryption with random salt.", true, actual);
	}
	
	/**
	 * Test case for decryption with random salt
	 * @throws Exception
	 */
	public void testDecryptWithRandomSalt() throws Exception {
		boolean actual = false;
		Random rand = new Random();
		int randomId = rand.nextInt(90000000); 
    	String outFile = targetDir+"/randomsalt-decryption-"+randomId+".txt";
		PasswordBasedEncryption.decryptWithRandomSalt(fileToDecrypt02, outFile, password);
		
		File file = new File(fileToEncrypt);
		byte[] plaintext = FileUtils.readFileToByteArray(file);
		file = new File(outFile);
		byte[] decryptedText = FileUtils.readFileToByteArray(file);
		String originalTextValue = new String(plaintext, "UTF-8");
		String decryptedTextValue = new String(decryptedText, "UTF-8");
		System.out.println("Random Salt - Original text was: "+ originalTextValue);
		System.out.println("Random Salt - Decrypted text is: "+decryptedTextValue);
		if (Arrays.equals(plaintext, decryptedText)) {
    		actual = true;
		}
    	assertEquals("Invalid decryption.", true, actual);
	}
	
	/**
	 * Test case for decryption with random salt to bytes array
	 * @throws Exception
	 */
	public void testDecryptWithRandomSaltToByteArray() throws Exception {
		boolean actual = false;
		byte[] decryptedText = PasswordBasedEncryption.decryptWithRandomSaltToByteArray(fileToDecrypt02, password);
		
		File file = new File(fileToEncrypt);
		byte[] plaintext = FileUtils.readFileToByteArray(file);
		String originalTextValue = new String(plaintext, "UTF-8");
		String decryptedTextValue = new String(decryptedText, "UTF-8");
		System.out.println("Random Salt (bytes array) - Original text was: "+ originalTextValue);
		System.out.println("Random Salt (bytes array) - Decrypted text is: "+ decryptedTextValue);
		if (Arrays.equals(plaintext, decryptedText)) {
    		actual = true;
		}
    	assertEquals("Invalid decryption.", true, actual);
	}
}
