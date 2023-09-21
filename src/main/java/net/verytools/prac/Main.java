package net.verytools.prac;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

public class Main {
    public static void main(String[] args) throws Exception {
        // 生成一个数据密钥（dataEncKey）用于加密数据
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // Key size in bits
        SecretKey dataEncKey = keyGenerator.generateKey();

        // 生成主密钥（wrappingKey）用于加密数据密钥
        KeyGenerator wrappingKeyGenerator = KeyGenerator.getInstance("AES");
        wrappingKeyGenerator.init(256); // Key size in bits
        SecretKey wrappingKey = wrappingKeyGenerator.generateKey();

        // 使用主密钥加密数据密钥得到加密后的数据密钥（wrappedKey）
        Cipher wrappingCipher = Cipher.getInstance("AESWrap");
        wrappingCipher.init(Cipher.WRAP_MODE, wrappingKey);
        byte[] wrappedKey = wrappingCipher.wrap(dataEncKey);

        // 使用数据密钥加密 plainText
        String plainText = "Hello, World!";
        String encryptedData = encrypt(plainText, dataEncKey.getEncoded());

        // 使用主密钥解密数据密钥，然后使用解密后的数据密钥（unwrappedKey）解密 encryptedData，然后验证解密后的数据是否和 plainText 相同
        wrappingCipher.init(Cipher.UNWRAP_MODE, wrappingKey);
        SecretKey unwrappedKey = (SecretKey) wrappingCipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        // Decrypt data using the wrapped key
        String decryptedData = decrypt(encryptedData, unwrappedKey.getEncoded());
        System.out.println(Objects.equals(plainText, decryptedData));
    }

    private static String encrypt(String plainText, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedText, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
