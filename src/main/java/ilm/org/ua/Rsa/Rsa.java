package ilm.org.ua.Rsa;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class Rsa {
    public KeyPair getKeyPair() {
        return keyPair;
    }

    KeyPair keyPair;

    public Rsa() {
        try {
            keyPair = generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public byte[] encrypt(byte[] plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText);

        return cipherText;
    }

    public byte[] decrypt(byte[] cipherText, PrivateKey privateKey) throws Exception {


        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return decriptCipher.doFinal(cipherText);
    }
}
