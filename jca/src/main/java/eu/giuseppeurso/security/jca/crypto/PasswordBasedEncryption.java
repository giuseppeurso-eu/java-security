package eu.giuseppeurso.security.jca.crypto;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This class implement a password-based encryption using the Bouncy Castle security provider.
 * Further info here:<br>
 * <a href="https://www.bouncycastle.org/specifications.html">https://www.bouncycastle.org/specifications.html</a>  
 * 
 * @author Giuseppe Urso
 *
 */
public class PasswordBasedEncryption {
	
	private static final String constantSalt = "This is a long fixed phrase that will be used each time as the salt. Both the encryption and decryption use the same salt.";
    private static final int iterations = 10000;
//  private static final int keyLength = 256;
    
	
	/**
	 * A password-based data encryption using a constant salt value "<b>constantSalt</b>"
	 * @param plainText
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encrypt(byte[] plainText, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
	    Security.addProvider(new BouncyCastleProvider());
	    PBEParameterSpec pbeParamSpec = new PBEParameterSpec(constantSalt.getBytes(), iterations);
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
	    SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
	    SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
	    Cipher encryptionCipher = Cipher.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
	    encryptionCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
	    return encryptionCipher.doFinal(plainText);
	}
	
	/**
	 * A password-based data decryption using a constant salt value "<b>constantSalt</b>"
	 * @param cipher
	 * @param password
	 * @param salt
	 * @param iterationCount
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] cipher, String password) throws Exception
	{
	    PKCS12ParametersGenerator pGen = new PKCS12ParametersGenerator(new SHA256Digest());
	    char[] passwordChars = password.toCharArray();
	    final byte[] pkcs12PasswordBytes = PBEParametersGenerator.PKCS12PasswordToBytes(passwordChars);
	    pGen.init(pkcs12PasswordBytes, constantSalt.getBytes(), iterations);
	    CBCBlockCipher aesCBC = new CBCBlockCipher(new AESEngine());
	    ParametersWithIV aesCBCParams = (ParametersWithIV) pGen.generateDerivedParameters(256, 128);
	    aesCBC.init(false, aesCBCParams);
	    PaddedBufferedBlockCipher aesCipher = new PaddedBufferedBlockCipher(aesCBC, new PKCS7Padding());
	    byte[] plainTemp = new byte[aesCipher.getOutputSize(cipher.length)];
	    int offset = aesCipher.processBytes(cipher, 0, cipher.length, plainTemp, 0);
	    int last = aesCipher.doFinal(plainTemp, offset);
	    final byte[] plain = new byte[offset + last];
	    System.arraycopy(plainTemp, 0, plain, 0, plain.length);
	    return plain;
	}
	
	/**
	 * A method for random salt.
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static byte[] generateSalt() throws NoSuchAlgorithmException {
	    byte salt[] = new byte[8];
	    SecureRandom saltGen = SecureRandom.getInstance("SHA1PRNG");
	    saltGen.nextBytes(salt);
	    return salt;
	}

	/**
	 * A password-based encryption using a random salt which is written in the output file itself. 
	 * The same password must be used with the salt again to decrypt the file.
	 * <b>PBEWithMD5AndTripleDES</b> requires "Unlimited Strength" Policy:<br>
	 *  <a href="http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html">http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html</a>
	 * @param fileIn
	 * @param fileOut
	 * @param password
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IOException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
 public static void encryptWithRandomSalt(String fileIn, String fileOut, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException{
	 	
	 	FileInputStream fis = new FileInputStream(fileIn);
		FileOutputStream fos= new FileOutputStream(fileOut);
		
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

		byte[] salt = generateSalt();
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 10000);
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
		fos.write(salt);

		byte[] input = new byte[64];
		int bytesRead;
		while ((bytesRead = fis.read(input)) != -1) {
			byte[] output = cipher.update(input, 0, bytesRead);
			if (output != null)
				fos.write(output);
		}
		byte[] output = cipher.doFinal();
		if (output != null)
			fos.write(output);

		fis.close();
		fos.flush();
		fos.close();
 }
 
 /**
  *  A password-based decryption using a random salt which is included into the input file itself. 
  * The receiver, uses the same password and salt of the sender and decrypts the content.
  * <b>PBEWithMD5AndTripleDES</b> requires "Unlimited Strength" Policy:<br>
  *  <a href="http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html">http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html</a>
  * @param fileIn
  * @param fileOut
  * @param password
  * @throws NoSuchAlgorithmException
  * @throws InvalidKeySpecException
  * @throws IOException
  * @throws NoSuchPaddingException
  * @throws InvalidKeyException
  * @throws InvalidAlgorithmParameterException
  * @throws IllegalBlockSizeException
  * @throws BadPaddingException
  */
 public static void decryptWithRandomSalt (String fileIn, String fileOut, String password ) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		
	 	PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
		FileInputStream fis = new FileInputStream(fileIn);
		byte[] salt = new byte[8];
		fis.read(salt);

		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 10000);

		Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
		FileOutputStream fos = new FileOutputStream(fileOut);
		byte[] in = new byte[64];
		int read;
		while ((read = fis.read(in)) != -1) {
			byte[] output = cipher.update(in, 0, read);
			if (output != null)
				fos.write(output);
		}

		byte[] output = cipher.doFinal();
		if (output != null)
			fos.write(output);
		fis.close();
		fos.flush();
		fos.close();
 }
 
 /**
  * A password-based decryption with random salt which is included into the input file itself. It returns a bytes array.
  * <b>PBEWithMD5AndTripleDES</b> requires "Unlimited Strength" Policy:<br>
  *  <a href="http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html">http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html</a>
  * @param fileIn
  * @param password
  * @return
  * @throws NoSuchAlgorithmException
  * @throws InvalidKeySpecException
  * @throws IOException
  * @throws NoSuchPaddingException
  * @throws InvalidKeyException
  * @throws InvalidAlgorithmParameterException
  * @throws IllegalBlockSizeException
  * @throws BadPaddingException
  */
 public static byte[] decryptWithRandomSaltToByteArray (String fileIn, String password ) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		
	 	PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
		FileInputStream fis = new FileInputStream(fileIn);
		byte[] salt = new byte[8];
		fis.read(salt);
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 10000);
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
		byte[] output = cipher.doFinal(IOUtils.toByteArray(fis));
		return output; 
}
 
}
