
package sample;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;

public class SHA {

	// Configuration
	public static final String SHA256ALGORITHM = "SHA-256";
	public static final String SHA512ALGORITHM = "SHA-512";
	public static final String SHA3256ALGORITHM = "SHA3-256";
	public static final String FOLDER_PATH = "E:\\Study\\Computer Security\\Assignments\\Assignment3\\";
	public static final String PLAIN_TEXT_FILE_SMALL = "SmallPlainTextFile.txt";
	public static final String PLAIN_TEXT_FILE_LARGE = "LargePlainTextFile.txt";
	public static final String HASH_SMALL = "ComputedHashForSmall.txt";
	public static final String HASH_LARGE = "ComputedHashForLarge.txt";

	public static void main(String[] args) throws InvalidKeyException, InvalidAlgorithmParameterException {

		try {

			ComputeHash(SHA256ALGORITHM, PLAIN_TEXT_FILE_SMALL, HASH_SMALL);
			ComputeHash(SHA256ALGORITHM, PLAIN_TEXT_FILE_LARGE, HASH_LARGE);
			ComputeHash(SHA512ALGORITHM, PLAIN_TEXT_FILE_SMALL, HASH_SMALL);
			ComputeHash(SHA512ALGORITHM, PLAIN_TEXT_FILE_LARGE, HASH_LARGE);
			ComputeHash(SHA3256ALGORITHM, PLAIN_TEXT_FILE_SMALL, HASH_SMALL);
			ComputeHash(SHA3256ALGORITHM, PLAIN_TEXT_FILE_LARGE, HASH_LARGE);

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void ComputeHash(String algorithmName, String plainTextFileName, String hashTextFileName)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException {
		byte fileContent[] = null;
		byte[] digestedBytes = null;
		FileOutputStream fileOutputStream = null;
		long timerStart = 0;
		long timerEnd = 0;
		long totalTime = 0;
		long hashingSpeed = 0;

		File file = new File(FOLDER_PATH.concat(plainTextFileName));
		try {

			if (!file.exists()) {
				System.out.println("Plain text file: " + file + " does not exists. Hashing not completed.");
				System.exit(0);
			}
			fileContent = Files.readAllBytes(file.toPath());
			timerStart = System.nanoTime();
			MessageDigest messageDigest = MessageDigest.getInstance(algorithmName);
			messageDigest.update(fileContent);
			digestedBytes = messageDigest.digest();
			timerEnd = System.nanoTime();
			totalTime = (timerEnd - timerStart) ;
			hashingSpeed = totalTime/fileContent.length;

		} catch (Exception ex) {

			System.out.println("An exception has occured: " + ex.getMessage() + ". File hashing not completed.");
		}

		try {

			fileOutputStream = new FileOutputStream(FOLDER_PATH.concat(algorithmName + "_" + hashTextFileName), false);
			fileOutputStream.write(digestedBytes, 0, digestedBytes.length);
			System.out.println("Time to hash " + plainTextFileName + " with " + algorithmName + "' :" + (totalTime/ 1000)
					+ " microseconds.");
			System.out.println("Hashing speed to hash '" + plainTextFileName + "' with algorithm " + algorithmName
					+ ":" + hashingSpeed + " nanoseconds per byte." + "\n");
			fileOutputStream.close();

		} catch (Exception ex) {

			System.out.println("An exception has occured: " + ex.getMessage() + ". File hashing not completed.");
		} finally {

			fileOutputStream.close();
		}
	}
}
