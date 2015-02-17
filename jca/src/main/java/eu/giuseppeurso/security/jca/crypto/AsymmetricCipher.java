package eu.giuseppeurso.security.jca.crypto;


import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;
import javax.crypto.Cipher;


/**
 * This class manages a basic asymmetric key cryptography (i.e. public key cryptography). To correctly encrypt/decrypt
 * clear text data or files, a key pair must be generated.
 * 
 * @author Giuseppe Urso
 */
public class AsymmetricCipher {
  
	/**
	 * This method must be used to create pairs of private and public keys. It returns a List of two objects, the PublicKey and the
	 * PrivateKey of java.security.KeyPair
	 * @param algorithm: RSA, DSA
	 * @param keysize: 512, 1024, 2048
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair keyPairGenerator (String algorithm, int keysize) throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
		kpg.initialize(keysize);
		KeyPair kp = kpg.generateKeyPair();
		return kp;
	}
	
	/**
	 * The method to encrypt data. It requires a previous generated private key and a transformation model.
	 * A transformation is a string that describes the operation to be performed on the given input.
	 * The transformation string is of the form: algorithm/mode/padding.<br><br>
	 * Transformation examples: <b>"DES/CFB8/NoPadding", "DES/OFB32/PKCS5Padding", "RSA/ECB/PKCS1Padding"</b><br>
	 * 
	 * @param inputBytes byte[]
	 * @param key PrivateKey
	 * @param xform A string like "DES/CFB8/NoPadding", "DES/OFB32/PKCS5Padding", "RSA/ECB/PKCS1Padding"
	 * @return byte[]
	 * @throws Exception
	 */
	public static byte[] encrypt (byte[] inputBytes, PublicKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inputBytes);
	}

	/**
	 * The method for data decryption. It requires a previous generated bublic key and the transformation model used for the previous encryption.
	 * A transformation is a string that describes the operation to be performed on the given input.
	 * The transformation string is of the form: algorithm/mode/padding.<br><br>
	 * Transformation examples: <b>"DES/CFB8/NoPadding", "DES/OFB32/PKCS5Padding", "RSA/ECB/PKCS1Padding"</b><br>
	 * @param inpBytes
	 * @param key
	 * @param xform
	 * @return byte[]
	 * @throws Exception
	 */
	public static byte[] decrypt (byte[] inputBytes, PrivateKey key,  String xform) throws Exception{
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(inputBytes);
	}
	
}
