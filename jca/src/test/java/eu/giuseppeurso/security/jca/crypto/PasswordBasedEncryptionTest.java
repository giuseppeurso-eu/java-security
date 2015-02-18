package eu.giuseppeurso.security.jca.crypto;

import java.io.File;
import java.util.Arrays;
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

	String resourceDir = "";
	String fileToEncrypt = "";
	String encryptedFile = "";
	String unencryptedFile = "";
	String password = "";
	
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
		fileToEncrypt = resourceDir + "/clear-text.txt";
		encryptedFile = resourceDir + "/encrypted-text.bin";
		unencryptedFile = resourceDir + "/unencrypted-text.txt";
		password = "12345";
	}   

	/**
	 * Test case for the encryption
	 * 
	 * @throws Exception
	 */
	public void testEncrypt() throws Exception {

		boolean actual = false;
		File file = new File(fileToEncrypt);
		byte[] plaintext = FileUtils.readFileToByteArray(file);
		byte[] salt = PasswordBasedEncryption.generateSalt();
		int iterationCount = 30;
		byte[] cipherText = PasswordBasedEncryption.encrypt(plaintext, password, salt, iterationCount);
		String cipherTextValue = new String(cipherText, "UTF-8");
		if (cipherText.length>0 && !cipherTextValue.contains("clear text!!!!")) {
    		actual = true;
		}
    	assertEquals("Invalid encryption.", true, actual);
		
	}

	 /** Test case for the decryption
	 * 
	 * @throws Exception
	 */
	public void testDecrypt() throws Exception {

		boolean actual = false;
		File file = new File(fileToEncrypt);
		byte[] plaintext = FileUtils.readFileToByteArray(file);
		byte[] salt = PasswordBasedEncryption.generateSalt();
		int iterationCount = 30;
		byte[] cipherText = PasswordBasedEncryption.encrypt(plaintext, password, salt, iterationCount);
		byte[] decryptedText = PasswordBasedEncryption.decrypt(cipherText, password, salt, iterationCount);
		
		String originalTextValue = new String(plaintext, "UTF-8");
		String decryptedTextValue = new String(decryptedText, "UTF-8");
		System.out.println("Original text was: "+ originalTextValue);
		System.out.println("Decrypted text is: "+decryptedTextValue);
		if (Arrays.equals(plaintext, decryptedText)) {
    		actual = true;
		}
    	assertEquals("Invalid decryption.", true, actual);
	}
}
