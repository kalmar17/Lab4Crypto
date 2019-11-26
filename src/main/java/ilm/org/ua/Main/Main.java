package ilm.org.ua.Main;

import ilm.org.ua.AES.AES;
import ilm.org.ua.Rsa.Rsa;
import ilm.org.ua.Sha1.Sha1;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

public class Main {
    private static String bytesToHex(byte[] hashInBytes) {

        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();

    }

    public static void main(String[] args) {
        try {
            String shaHex = Sha1.encryptThisString("sha");
            AES aes = new AES();
            byte[] aesEncryptText = aes.makeAes(shaHex.getBytes(), Cipher.ENCRYPT_MODE);
            Rsa rsa = new Rsa();
            System.out.println(Arrays.toString(aes.getSecretKey().getEncoded()));
            byte[] rsaEncText = rsa.encrypt(aes.getSecretKey().getEncoded(), rsa.getKeyPair().getPublic());
            byte[] aesSecretKey = rsa.decrypt(rsaEncText, rsa.getKeyPair().getPrivate());
            System.out.println(Arrays.toString(aesSecretKey));
            SecretKey secretKey = new SecretKeySpec(aesSecretKey, "AES");
            AES aes2 = new AES();
            aes2.setSecretKey(secretKey);
            System.out.println(aes.getSecretKey().equals(aes2.getSecretKey()));
            byte[] aesDexryptText = aes2.makeAes(aesEncryptText, Cipher.DECRYPT_MODE);
            System.out.println(Arrays.toString(shaHex.getBytes()));
            System.out.println(Arrays.toString(aesDexryptText));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
