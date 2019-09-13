package sample;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class AES128EncryptionDemo {

	public static void main(String[] args) {
		try {

			String plainText = "saurabhgotherwal";

			// generate Key
			KeyGenerator aesKey = KeyGenerator.getInstance("AES");
			aesKey.init(128);
			SecretKey aesSecretkey = aesKey.generateKey();
			long start = System.currentTimeMillis();
			// Encrypt Data
			int ctr = 0;
			while (ctr < 1000) {

				Cipher cipherText = Cipher.getInstance("AES/ECB/PKCS5Padding");
				cipherText.init(Cipher.ENCRYPT_MODE, aesSecretkey);
				byte[] cipherTextInBytes = cipherText.doFinal(plainText.getBytes("UTF-8"));
				ctr += 1;
			}
			long stend = System.currentTimeMillis();
			// print Data
			// System.err.println("Cipher Text: " + new String(cipherTextInBytes));

			System.out.println(stend - start);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
}
