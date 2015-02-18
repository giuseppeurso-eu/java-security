package eu.giuseppeurso.security.jca.crypto;

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
	
	/**
	 * A method to execute a password-based data encryption.
	 * @param plainText
	 * @param password
	 * @param salt
	 * @param iterationCount
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encrypt(byte[] plainText, String password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
	    Security.addProvider(new BouncyCastleProvider());
	    PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
	    SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
	    SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
	    Cipher encryptionCipher = Cipher.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
	    encryptionCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
	    return encryptionCipher.doFinal(plainText);
	}
	
	/**
	 * A method to execute a password-based data decryption.
	 * @param cipher
	 * @param password
	 * @param salt
	 * @param iterationCount
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] cipher, String password, byte[] salt, final  int iterationCount) throws Exception
	{
	    PKCS12ParametersGenerator pGen = new PKCS12ParametersGenerator(new SHA256Digest());
	    char[] passwordChars = password.toCharArray();
	    final byte[] pkcs12PasswordBytes = PBEParametersGenerator.PKCS12PasswordToBytes(passwordChars);
	    pGen.init(pkcs12PasswordBytes, salt, iterationCount);
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
	 * The method for salt generation.
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] generateSalt() throws NoSuchAlgorithmException {
	    byte salt[] = new byte[8];
	    SecureRandom saltGen = SecureRandom.getInstance("SHA1PRNG");
	    saltGen.nextBytes(salt);
	    return salt;
	}
	

}
