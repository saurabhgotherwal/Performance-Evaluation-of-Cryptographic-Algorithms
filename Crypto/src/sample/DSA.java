package sample;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;

public class DSA {

	public static final String FOLDER_PATH = "E:\\Study\\Computer Security\\Assignments\\Assignment3\\";
	public static final String PLAIN_TEXT_FILE_SMALL = "SmallPlainTextFile.txt";
	public static final String PLAIN_TEXT_FILE_LARGE = "LargePlainTextFile.txt";
	public static final String SIGNED_SMALL = "DSASignatureForSmall.txt";
	public static final String SIGNED_LARGE = "DSASignatureForLarge.txt";
	public static final String ALGORITHM = "SHA256withDSA";
	public static final String PROVIDER = "SUN";
	public static final int KEY_SIZE = 2048;

	public static void main(String[] args) throws Exception {

		KeyPair keyPairForDsa = GenerateKeyPair("DSA", "SUN");
		PublicKey publicKey = keyPairForDsa.getPublic();
		PrivateKey privateKey = keyPairForDsa.getPrivate();
		SignUsingDSA(privateKey, publicKey, ALGORITHM, PROVIDER, PLAIN_TEXT_FILE_LARGE, SIGNED_LARGE);
		SignUsingDSA(privateKey, publicKey, ALGORITHM, PROVIDER, PLAIN_TEXT_FILE_SMALL, SIGNED_SMALL);
	}
	
	public static KeyPair GenerateKeyPair(String algorithm, String provider)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		long timerStart = 0;
		long timerEnd = 0;
		timerStart = System.nanoTime();
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm, provider);
		keyGenerator.initialize(KEY_SIZE , SecureRandom.getInstance("SHA1PRNG", provider));
		timerEnd = System.nanoTime();
		System.out.println("Time to generate a key pair: " + (timerEnd - timerStart) / 1000 + "microseconds");
		return keyGenerator.genKeyPair();
	}
	
	
	
	public static byte[] GetSignatureForFile(PrivateKey privateKey, String algorithmName, String fileName,
			String provider) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
			NoSuchProviderException, IOException {
		long timerStart = 0;
		long timerEnd = 0;
		long totalTime = 0;
		long signingSpeed = 0;
		
		Signature dsaSignature = Signature.getInstance(algorithmName, provider);
		dsaSignature.initSign(privateKey);
		FileInputStream fileInputStream = new FileInputStream(FOLDER_PATH + fileName);
		File file = new File(FOLDER_PATH.concat(fileName));
		if (!file.exists()) {
			System.out.println("Plain text file: " + file + " does not exists. Encryption not completed.");
			System.exit(0);
		}
		byte[] fileContent = new byte[((int) file.length())];
		fileInputStream.read(fileContent);
		dsaSignature.update(fileContent, 0, fileContent.length);
		fileInputStream.close();
		timerStart = System.nanoTime();
		byte[] signature = dsaSignature.sign();
		timerEnd = System.nanoTime();
		totalTime = (timerEnd - timerStart);
		signingSpeed = totalTime / fileContent.length;
		System.out.println("\nTime to sign '" + fileName + "' :" + (totalTime / 1000) + " microseconds.");
		System.out.println("\n Speed to sign '" + fileName + "' :" + signingSpeed + " nanoseconds/byte." );

		return signature;
	}

	public static void SaveContentInFile(byte[] fileContent, String fileName) throws IOException {
		FileOutputStream fileOutputStream = new FileOutputStream(FOLDER_PATH + fileName);
		fileOutputStream.write(fileContent);
		fileOutputStream.close();
	}

	public static byte[] GetContentFromFile(String fileName) throws IOException {
		FileInputStream fileInputStream = new FileInputStream(FOLDER_PATH + fileName);
		byte[] fileContent = new byte[fileInputStream.available()];
		fileInputStream.read(fileContent);
		fileInputStream.close();
		return fileContent;
	}

	

	public static void SignUsingDSA(PrivateKey privateKey, PublicKey publicKey, String algorithm, String provider,
			String fileName, String signatureFileName) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
		byte[] dsaSignature = GetSignatureForFile(privateKey, algorithm, fileName, provider);

		SaveContentInFile(dsaSignature, signatureFileName);
		// Save the signature in a file
		SaveContentInFile(publicKey.getEncoded(), "publicKeyDSA.txt");
		boolean result = VerifyDSASignature(algorithm, signatureFileName, provider, fileName);
		System.out.println(fileName + ": Signature validation: " + result + "\n");
	}

	public static boolean VerifyDSASignature(String algorithmName, String signatureFileName, String provider,
			String fileName) {

		boolean result = false;

		try {

			FileInputStream fileInputStream = new FileInputStream(FOLDER_PATH + fileName);
			File file = new File(FOLDER_PATH.concat(fileName));
			if (!file.exists()) {
				System.out.println("Plain text file: " + file + " does not exists. Encryption not completed.");
				System.exit(0);
			}

			byte[] fileContent = new byte[((int) file.length())];
			fileInputStream.read(fileContent);
			fileInputStream.close();

			byte[] publicEncryptionKey = GetContentFromFile("publicKeyDSA.txt");
			X509EncodedKeySpec publicKeySpecification = new X509EncodedKeySpec(publicEncryptionKey);
			KeyFactory keyFactory = KeyFactory.getInstance("DSA", provider);
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpecification);

			byte[] signatureToVerify = GetContentFromFile(signatureFileName);
			Signature signature = Signature.getInstance(algorithmName, provider);
			signature.initVerify(publicKey);
			signature.update(fileContent, 0, fileContent.length);
			result = signature.verify(signatureToVerify);

		} catch (Exception ex) {
			System.err.println("An error occured" + ex.toString());
		}
		return result;
	}
}
