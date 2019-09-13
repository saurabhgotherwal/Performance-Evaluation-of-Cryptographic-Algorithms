package sample;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSA2048 {

	public static final int KEY_SIZE = 128;
	public static final String FOLDER_PATH = "E:\\Study\\Computer Security\\Assignments\\Assignment3\\";
	public static final String PLAIN_TEXT_FILE_SMALL = "SmallPlainTextFile.txt";
	public static final String PLAIN_TEXT_FILE_LARGE = "LargePlainTextFile.txt";
	public static final String ENCRYPTED_TEXT_FILE_SMALL = "SmallEncryptedFileCTR256.txt";
	public static final String DECRYPTED_TEXT_FILE_SMALL = "SmallDecryptedFileCTR256.txt";
	public static final String ENCRYPTED_TEXT_FILE_LARGE = "LargeEncryptedFileCTR256.txt";
	public static final String DECRYPTED_TEXT_FILE_LARGE = "LargeDecryptedFileCTR256.txt";

	public static void main(String[] args)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {

		FileInputStream fis = new FileInputStream(FOLDER_PATH + PLAIN_TEXT_FILE_SMALL);
		Security.addProvider(new BouncyCastleProvider());
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(3072);/// Can be modified to generate 2048 key also
		Long keyGenerationTime = System.nanoTime();
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		Long keyGenerationTimeEnd = System.nanoTime();
		System.out.println("key generation time : " + (keyGenerationTimeEnd - keyGenerationTime) + " nanoseconds");
				
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		// Encryption
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] dataArray = new byte[200];
		byte[] responseArray = new byte[1000];
		List<byte[]> byteArrayList = new ArrayList<byte[]>();
		Long totalEncryptionTime = 0L;
		while (fis.read(dataArray) > 0) {
			Long encryptionTime = System.nanoTime();
			responseArray = cipher.doFinal(dataArray);
			Long encryptionTimeEnd = System.nanoTime();
			totalEncryptionTime = totalEncryptionTime + (encryptionTimeEnd - encryptionTime);
			byteArrayList.add(responseArray);
		}
		fis.close();
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(FOLDER_PATH + ENCRYPTED_TEXT_FILE_SMALL));
		out.writeObject(byteArrayList);
		out.close();
		System.out.println("Time for encryption-: " + totalEncryptionTime + " nanoseconds");
		ObjectInputStream objectInputStream = new ObjectInputStream(
				new FileInputStream(FOLDER_PATH + ENCRYPTED_TEXT_FILE_SMALL));
		byteArrayList = (List<byte[]>) objectInputStream.readObject();
		objectInputStream.close();

		// Decryption
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		Long decryptionTime = 0L;
		for (byte[] b1 : byteArrayList) {
			Long deryptTimeStart = System.nanoTime();
			Long decryptTimeEnd = System.nanoTime();
			decryptionTime = decryptionTime + (decryptTimeEnd - deryptTimeStart);
		}
		System.out.println("Time for decryption-: " + decryptionTime + " nanoseconds");
	}

}
