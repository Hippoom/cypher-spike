package spike.cypher;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class RsaEncryptor {

    private String provider;
    private int blockSize;

    public RsaEncryptor(String provider, int blockSize) {
        this.blockSize = blockSize;
        this.provider = provider;
    }

    public ByteArrayOutputStream encrypt(Key publicKey, ByteArrayInputStream inputStream) throws IOException, NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            Cipher cipher = cipher(Cipher.ENCRYPT_MODE, publicKey);
            transform(cipher, inputStream, outputStream);

            return outputStream;
        }
    }

    public ByteArrayOutputStream decrypt(Key privateKey, ByteArrayInputStream inputStream) throws IOException, NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            Cipher cipher = cipher(Cipher.DECRYPT_MODE, privateKey);
            transform(cipher, inputStream, outputStream);

            return outputStream;
        }
    }

    public Cipher cipher(int mode, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
        cipher.init(mode, key);
        return cipher;
    }

    /**
     * Streams is preferred for parameters so that it will be easier to support {@link java.io.File} after
     */
    private void transform(Cipher cipher, ByteArrayInputStream toBeEncryptedInputStream, ByteArrayOutputStream encryptedOutputStream) throws IOException, IllegalBlockSizeException, BadPaddingException {
        CipherUtils.transform(cipher, toBeEncryptedInputStream, encryptedOutputStream, blockSize);
    }
}
