// javac -cp ".:bcprov-jdk18on-1.83.jar" ARIATest.java
//
// java -cp ".:bcprov-jdk18on-1.83.jar" ARIATest

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Base64;

public class ARIATest {
    public static void main(String[] args) {
        try {
            // 1. Initialize Bouncy Castle Provider
            Security.addProvider(new BouncyCastleProvider());

            String plainText = "Surely goodness and mercy shall follow me all the days of my life: And I will dwell in the house of the LORD for ever.";

            // 2. Generate Key and Nonce (IV for GCM)
            byte[] keyBytes = new byte[16]; // 128-bit key
            byte[] ivBytes = new byte[12]; // GCM recommended IV size is 12 bytes

            SecureRandom random = new SecureRandom();
            random.nextBytes(keyBytes);
            random.nextBytes(ivBytes);

            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "ARIA");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes); // 128-bit auth tag

            // 3. Encryption
            Cipher encryptCipher = Cipher.getInstance("ARIA/GCM/NoPadding", "BC");
            encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] cipherText = encryptCipher.doFinal(plainText.getBytes());

            System.out.println("--- ARIA Encryption Demo ---");
            System.out.println("Original:  " + plainText);
            System.out.println("Encrypted (Base64): " + Base64.getEncoder().encodeToString(cipherText));

            // 4. Decryption
            Cipher decryptCipher = Cipher.getInstance("ARIA/GCM/NoPadding", "BC");
            decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] decryptedBytes = decryptCipher.doFinal(cipherText);

            System.out.println("Decrypted: " + new String(decryptedBytes));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}