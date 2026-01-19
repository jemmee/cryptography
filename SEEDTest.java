// javac -cp ".:bcprov-jdk18on-1.83.jar" SEEDTest.java
//
// java -cp ".:bcprov-jdk18on-1.83.jar" SEEDTest

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Base64;

public class SEEDTest {
    public static void main(String[] args) throws Exception {
        // 1. Add Bouncy Castle as a Security Provider
        Security.addProvider(new BouncyCastleProvider());

        String message = "Yea, though I walk through the valley of the shadow of death, I will fear no evil: for thou art with me; Thy rod and thy staff they comfort me.";
        byte[] keyBytes = "KoreaSeedKey128!".getBytes(); // 16 bytes
        byte[] ivBytes = new byte[16]; // In production, use SecureRandom

        // 2. Setup Key and IV
        SecretKeySpec key = new SecretKeySpec(keyBytes, "SEED");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // 3. Encryption (Algorithm/Mode/Padding)
        Cipher encryptCipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = encryptCipher.doFinal(message.getBytes());

        System.out.println("Ciphertext (Base64): " + Base64.getEncoder().encodeToString(ciphertext));

        // 4. Decryption
        Cipher decryptCipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");
        decryptCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedBytes = decryptCipher.doFinal(ciphertext);

        System.out.println("Decrypted: " + new String(decryptedBytes));
    }
}