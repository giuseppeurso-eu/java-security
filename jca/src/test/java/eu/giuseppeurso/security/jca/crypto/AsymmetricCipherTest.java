package eu.giuseppeurso.security.jca.crypto;

import java.io.File;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import org.apache.commons.io.FileUtils;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for AsymmetricCipher.
 * 
 * @author Giuseppe Urso
 * 
 */
public class AsymmetricCipherTest extends TestCase {

	String resourceDir = "";
	String fileToEncrypt = "";
	String encryptedFile = "";
	String unencryptedFile = "";
	
	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite() {
		return new TestSuite(AsymmetricCipherTest.class);
	}
	
	/**
	 * Setup test cases
	 */
	public void setUp() {
		resourceDir = "src/test/resources";
		fileToEncrypt = resourceDir + "/clear-text.txt";
		encryptedFile = resourceDir + "/encrypted-text.bin";
		unencryptedFile = resourceDir + "/unencrypted-text.txt";
	}   

	/**
	 * Test case for method keyPairGenerator()
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws Exception
	 */
	public void testKeyPairGenerator() throws NoSuchAlgorithmException {

		KeyPair keyPair = AsymmetricCipher.keyPairGenerator("RSA", 2048);
		PrivateKey privk = keyPair.getPrivate();
		PublicKey pubk = keyPair.getPublic();
		boolean actual = false;
		if (privk.getAlgorithm().equals("RSA")	&& pubk.getAlgorithm().equals("RSA")) {
			actual = true;
		}
		assertEquals("Error on key pair generation.", true, actual);
	}

	/**
	 * Test case for method encrypt()
	 * 
	 * @throws Exception
	 */
	public void testEncrypt() throws Exception {
		byte[] inputData = "This is a clear text!!!".getBytes();
		KeyPair keyPair = AsymmetricCipher.keyPairGenerator("RSA", 2048);
		byte[] encryptedData = AsymmetricCipher.encrypt(inputData,	keyPair.getPublic(), "RSA/ECB/PKCS1Padding");
		String encryptedText = new String(encryptedData, "UTF-8");
		boolean actual = false;
		if (encryptedData.length > 0 && !encryptedText.contains("testo")) {
			actual = true;
		}
		assertEquals("Invalid encryption.", true, actual);
	}

	/**
	 * Test case for method decrypt()
	 * 
	 * @throws Exception
	 */
	public void testDecrypt() throws Exception {
		byte[] inputData = "This is a clear text!!!".getBytes();
		KeyPair keyPair = AsymmetricCipher.keyPairGenerator("RSA", 2048);
		byte[] encryptedData = AsymmetricCipher.encrypt(inputData, keyPair.getPublic(), "RSA/ECB/PKCS1Padding");
		byte[] decryptedData = AsymmetricCipher.decrypt(encryptedData, keyPair.getPrivate(), "RSA/ECB/PKCS1Padding");
		boolean actual = false;
		if (Arrays.equals(inputData, decryptedData)) {
			actual = true;
		}
		assertEquals("Invalid decryption.", true, actual);
	}

	/**
	 * Test a file encyption/decryption
	 * 
	 */
	public void testFileEncyption() throws Exception {
		boolean actual=false;

		// Generate a key-pair
		KeyPair kp = AsymmetricCipher.keyPairGenerator("RSA", 2048);
		PublicKey pubk = kp.getPublic();
		PrivateKey prvk = kp.getPrivate();
		
		File file = new File(fileToEncrypt);
		byte[] dataBytes = FileUtils.readFileToByteArray(file);
		System.out.println("Source file size is: " + dataBytes.length * 8+ " bits (=" + dataBytes.length + " bytes)");
		System.out.println("RSA key size is: " + 2048 + " bits (= "+ 2048 / 8 + " bytes)");
		
		// Now start with the file encryption
		String xform = "RSA/ECB/PKCS1Padding";
		byte[] encBytes = AsymmetricCipher.encrypt(dataBytes, pubk, xform);
		file = new File(encryptedFile);
		FileUtils.writeByteArrayToFile(file, encBytes);
		System.out.println("Encrypted file at: " + encryptedFile);

		// Decrypt the generated file
		byte[] decBytes = AsymmetricCipher.decrypt(encBytes, prvk, xform);
		file = new File(unencryptedFile);
		FileUtils.writeByteArrayToFile(file, decBytes);
		System.out.println("Unencrypted file at: " + unencryptedFile);

		// Comparing the encrypted/decrypted bytes
		actual = java.util.Arrays.equals(dataBytes, decBytes);
		assertEquals("Invalid decryption.", true, actual);
	}
}
