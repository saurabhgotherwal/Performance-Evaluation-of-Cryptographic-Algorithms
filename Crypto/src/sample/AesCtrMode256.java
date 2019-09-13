package sample;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AesCtrMode256 {
	
	//Encryption/Decryption Configuration
	public static final String ALGORITHM = "AES";
	public static final String MODE = "CTR"; 
	public static final String PADDING = "PKCS5Padding";
	public static final int KEY_SIZE = 128;
	public static final int BLOCK_SIZE = 16;
	public static final String FOLDER_PATH = "E:\\Study\\Computer Security\\Assignments\\Assignment3\\";
	public static final String PLAIN_TEXT_FILE_SMALL = "SmallPlainTextFile.txt";
	public static final String PLAIN_TEXT_FILE_LARGE = "LargePlainTextFile.txt";
	public static final String ENCRYPTED_TEXT_FILE_SMALL = "SmallEncryptedFileCTR256.txt";
	public static final String DECRYPTED_TEXT_FILE_SMALL = "SmallDecryptedFileCTR256.txt";
	public static final String ENCRYPTED_TEXT_FILE_LARGE = "LargeEncryptedFileCTR256.txt";
	public static final String DECRYPTED_TEXT_FILE_LARGE = "LargeDecryptedFileCTR256.txt";
		
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		
		long timerStart = 0;
		long timerEnd = 0;
		//Generate a 128-bit secret key using key generator
		KeyGenerator key = KeyGenerator.getInstance(ALGORITHM);
		key.init(KEY_SIZE);
		
		timerStart = System.nanoTime();
		
		SecretKey secretKey = key.generateKey();
		timerEnd = System.nanoTime();	
			
		System.out.println("Time to generate a new key: " + (timerEnd - timerStart)/1000 + "microseconds");
		
		//Generate a 16 byte long initialization vector
		byte[] bytes = new byte[BLOCK_SIZE];
		SecureRandom random = new SecureRandom();
		random.nextBytes(bytes);		
		IvParameterSpec initializationVector = new IvParameterSpec(bytes);
		
		// Create and Initialize the Cipher object
		String transformation = ALGORITHM.concat("/").concat(MODE).concat("/").concat(PADDING);		
		Cipher cipher = Cipher.getInstance(transformation);
		
		try {
			
			EncryptTextFile(cipher,secretKey,initializationVector, PLAIN_TEXT_FILE_SMALL, ENCRYPTED_TEXT_FILE_SMALL);			
			
			DecryptTextFile(cipher,secretKey,initializationVector, ENCRYPTED_TEXT_FILE_SMALL, DECRYPTED_TEXT_FILE_SMALL);
			
			EncryptTextFile(cipher,secretKey,initializationVector, PLAIN_TEXT_FILE_LARGE, ENCRYPTED_TEXT_FILE_LARGE);			
			
			DecryptTextFile(cipher,secretKey,initializationVector, ENCRYPTED_TEXT_FILE_LARGE, DECRYPTED_TEXT_FILE_LARGE);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	}
	
	public static void EncryptTextFile(Cipher cipher, SecretKey secretKey, IvParameterSpec initializationVector,
			String PlainTextFileName, String EncryptedTextFileName)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException {
		byte fileContent[] = null;
		byte[] encryptedBytes = null;
		FileInputStream fileInputStream = null;
		FileOutputStream fileOutputStream = null;
		long timerStart = 0;
		long timerEnd = 0;
		long totalTime = 0;
		long encryptionSpeed = 0;

		cipher.init(Cipher.ENCRYPT_MODE, secretKey, initializationVector);

		File file = new File(FOLDER_PATH.concat(PlainTextFileName));
		try {

			if (!file.exists()) {
				System.out.println("Plain text file: " + file + " does not exists. Encryption not completed.");
				System.exit(0);
			}

			fileContent = Files.readAllBytes(file.toPath());

			// fileInputStream = new FileInputStream(file);

			// fileContent = new byte[((int)file.length())];
			// fileInputStream.read(fileContent);

			timerStart = System.nanoTime();

			encryptedBytes = Base64.getEncoder().encode(cipher.doFinal(fileContent));

			timerEnd = System.nanoTime();

			totalTime = (timerEnd - timerStart) / 1000;

			encryptionSpeed = encryptedBytes.length / totalTime;

		} catch (Exception ex) {

			System.out.println("An exception has occured: " + ex.getMessage() + ". File encryption not completed.");
		} finally {

			// fileInputStream.close();
		}

		try {

			fileOutputStream = new FileOutputStream(FOLDER_PATH.concat(EncryptedTextFileName), false);

			fileOutputStream.write(encryptedBytes, 0, encryptedBytes.length);

			// System.out.println("\nFile encryption completed. The content is placed in:" +
			// EncryptedTextFileName);

			System.out.println("\nTime to encrypt '" + PlainTextFileName + "' :" + totalTime + " microseconds.");

			System.out.println("\nEncryption speed to encrypt '" + PlainTextFileName + "' :" + encryptionSpeed
					+ " bytes per microsecond.");

			fileOutputStream.close();

		} catch (Exception ex) {

			System.out.println("An exception has occured: " + ex.getMessage() + ". File encryption not completed.");
		} finally {

			fileOutputStream.close();
		}

	}
	
	public static void DecryptTextFile(Cipher cipher, SecretKey secretKey, IvParameterSpec initializationVector, String EncryptedTextFileName, String DecryptedTextFileName) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException
	{
		long timerStart = 0;
		long timerEnd = 0;
		long decryptionSpeed = 0;
		long totalTime = 0;
		
		byte fileContent[] = null;
		byte[] decryptedBytes = null;		
		FileInputStream fileInputStream = null;
		FileOutputStream fileOutputStream = null;
		
		cipher.init(Cipher.DECRYPT_MODE, secretKey, initializationVector);
		
		File file = new File(FOLDER_PATH.concat(EncryptedTextFileName));
		
		try {
			
			fileContent = Files.readAllBytes(file.toPath());
			
			//fileInputStream= new FileInputStream(file);		
			//fileContent = new byte[((int)file.length())];
			//fileInputStream.read(fileContent);
			
			timerStart = System.nanoTime();
			
			decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(fileContent));
			
			timerEnd = System.nanoTime();	
			
			totalTime = (timerEnd - timerStart)/1000;
			
			decryptionSpeed = decryptedBytes.length/totalTime ;
			
		} catch(Exception ex){
			
			System.out.println("An exception has occured: " + ex.getMessage() + ". File decryption not completed.");
		} finally {
			
			//fileInputStream.close();
		}
		
		try
		{			
			fileOutputStream = new FileOutputStream(FOLDER_PATH.concat(DecryptedTextFileName),false);			
			fileOutputStream.write(decryptedBytes,0,decryptedBytes.length);		
			//System.out.println("File decryption completed. The content is placed in:" + DecryptedTextFileName);	
			
			System.out.println("\nTime to decrypt '"+ EncryptedTextFileName + "' :" + totalTime + " microseconds.");
			
			System.out.println("\nDecryption speed to decrypt '"+ EncryptedTextFileName + "' :" + decryptionSpeed + " bytes per microsecond.");
			
		} catch(Exception ex){
			
			System.out.println("An exception has occured: " + ex.getMessage() + ". File decryption not completed.");
		} finally {
			
			fileOutputStream.close();
		}			
	}	
}
