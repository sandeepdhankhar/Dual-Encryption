
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 * 
 * The class provides mechanism to encrypt data with two keys where one key
 * could be static and other could be unique for every user
 *
 */

public enum DualKeyEncryption {

	INSTANCE;

	private final Logger logger = Logger.getLogger(DualKeyEncryption.class.getName());

	private Cipher encryptionCipher = null;
	private Cipher decryptionCipher = null;

	private Object encryptionLock = new Object();
	private Object decryptionLock = new Object();
	private Random random = new Random();
	private String AB = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";

	public String randomKey(int length) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < length; i++) {
			builder.append(AB.charAt(random.nextInt(62)));
		}

		return builder.toString();
	}

	public String generateVariableLengthKey() {
		int length = random.nextInt(100);
		return randomKey(60 + length);
	}

	private DualKeyEncryption() {

		try {
			init();
		} catch (Exception e) {
			logger.warning(e.getMessage());
		}
	}

	private void init() {
		try {
			// get the key from from the file/system
			// TODO the null is just a placeholder, replace it with appropriate
			// source
			String secrtKey = null;
			if (secrtKey == null) {

				logger.warning("The secret key is still null,generate temp one");
				secrtKey = randomKey(128);
			}
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			MessageDigest md;

			md = MessageDigest.getInstance("SHA");

			md.update(secrtKey.getBytes("UTF-8"));
			byte[] digest = md.digest();
			byte[] result = digest;
			if (digest.length > 16) {
				result = new byte[16];
				for (int i = 0; i < 16; i++) {
					result[i] = digest[i];
				}
			} else {
				logger.warning("The key length is less than 16");
			}
			SecretKeySpec secretKeySpec = new SecretKeySpec(result, "AES");

			encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec);

			decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			decryptionCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);

		} catch (NoSuchAlgorithmException e) {
			logger.info(e.getMessage());
		} catch (InvalidKeyException e) {
			logger.info(e.getMessage());
		} catch (InvalidAlgorithmParameterException e) {
			logger.info(e.getMessage());
		} catch (NoSuchPaddingException e) {
			logger.info(e.getMessage());
		} catch (UnsupportedEncodingException e) {
			logger.info(e.getMessage());
		} catch (Throwable e) {
			logger.info(e.getMessage());
		}

	}

	/**
	 * This method returns the encrypted string
	 * 
	 * @param message
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public final String encrypt(final String message) throws IllegalBlockSizeException, BadPaddingException {

		byte[] stringBytes = message.getBytes();
		byte[] raw;
		synchronized (encryptionLock) {
			raw = encryptionCipher.doFinal(stringBytes);
		}

		return DatatypeConverter.printBase64Binary(raw);

	}

	/**
	 * The method returns the decrypted string
	 * 
	 * @param encrypted
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	public final String decrypt(final String encrypted) throws IllegalBlockSizeException, BadPaddingException,
			UnsupportedEncodingException {

		byte[] raw = DatatypeConverter.parseBase64Binary(encrypted);
		byte[] stringBytes;
		synchronized (decryptionLock) {
			stringBytes = decryptionCipher.doFinal(raw);
		}
		String clearText = new String(stringBytes, "UTF8");
		return clearText;
	}

	/**
	 * This method encrypts the message using the encryption key and then
	 * obscures the encrypted result with the input key This makes it almost
	 * impossible to decrypt the original message even with the encryption key
	 * unless the second key is present
	 * 
	 * @param key
	 * @param message
	 * @return
	 * @throws Exception
	 */
	public final String dualKeyEncrypt(final String key, String message) throws Exception {
		try {

			String enc = encrypt(message);
			byte[] keyByte = key.getBytes();
			String encoded = DatatypeConverter.printBase64Binary(keyByte);
			int index = random.nextInt(enc.length());
			String encodedPart = encoded.substring(0, encoded.length() - 2);
			String result = enc.substring(0, index) + encodedPart + enc.substring(index);

			// There can be a very small possibility that the key is small
			// enough and similar combination already exists in the original
			// string
			if (result.indexOf(encodedPart) != result.lastIndexOf(encodedPart)) {
				// This is blatant misuse of recursion but if the user key is
				// distinct enough then the flow would never enter in this
				// condition
				result = dualKeyEncrypt(key, message);
			}
			return result;

		} catch (Exception e) {
			logger.info(e.getMessage());
			throw new Exception("Encryption Failure");
		}
	}

	/**
	 * 
	 * @param key
	 * @param encrypted
	 * @return
	 * @throws Exception
	 */
	public final String dualKeyDecrypt(final String key, String encrypted) throws Exception {

		try {
			byte[] keyByte = key.getBytes();

			String encoded = DatatypeConverter.printBase64Binary(keyByte);
			encrypted = encrypted.replace(encoded.substring(0, encoded.length() - 2), "");
			return decrypt(encrypted);

		} catch (Exception e) {
			logger.info(e.getMessage());
			throw new Exception("Decryption Failure");
		}

	}

}