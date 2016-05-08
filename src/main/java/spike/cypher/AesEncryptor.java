package spike.cypher;

import com.google.common.io.ByteStreams;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Base64;

import static javax.crypto.Cipher.ENCRYPT_MODE;

public class AesEncryptor {
    private String provider;
    private int ivLength;
    private int blockSize;

    public AesEncryptor(String provider, int ivLength, int blockSize) {
        this.blockSize = blockSize;
        this.ivLength = ivLength;
        this.provider = provider;
    }

    public ByteArrayOutputStream encrypt(SecretKey secretKey, ByteArrayInputStream toBeEncryptedInputStream) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] iv = iDontKnowWhyIvIsGeneratedInThisWay(secretKey);
        Cipher cipher = cipher(provider, secretKey, ENCRYPT_MODE, new IvParameterSpec(iv));

        try (ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream()) {
            encryptedOutputStream.write(iv); // the beginning of the stream is IV?
            transform(cipher, toBeEncryptedInputStream, encryptedOutputStream);
            return encryptedOutputStream;
        }
    }

    public ByteArrayOutputStream decrypt(SecretKey secretKey, ByteArrayInputStream encryptedInputStream) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        try (ByteArrayOutputStream decryptedOutputStream = new ByteArrayOutputStream()) {
            Cipher cipher = cipherForDecryption(secretKey, encryptedInputStream);

            transform(cipher, encryptedInputStream, decryptedOutputStream);
            return decryptedOutputStream;
        }
    }

    private Cipher cipherForDecryption(SecretKey secretKey, ByteArrayInputStream encryptedInputStream) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] ivInStream = fetchIvFromStream(encryptedInputStream);
        return cipher(provider, secretKey, Cipher.DECRYPT_MODE, new IvParameterSpec(ivInStream));
    }

    private byte[] fetchIvFromStream(ByteArrayInputStream encryptedInputStream) throws IOException {
        byte[] ivInStream = new byte[ivLength];
        ByteStreams.readFully(encryptedInputStream, ivInStream);
        return ivInStream;
    }


    private byte[] iDontKnowWhyIvIsGeneratedInThisWay(SecretKey secretKey) {
        return Arrays.copyOfRange(Base64.getEncoder().encode(secretKey.getEncoded()), 0, ivLength);
    }

    private Cipher cipher(String provider, SecretKey secretKey, int mode, IvParameterSpec algorithmParameterSpec) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING", provider);
        cipher.init(mode, secretKey, algorithmParameterSpec);
        return cipher;
    }

    /**
     * Streams is preferred for parameters so that it will be easier to support {@link java.io.File} after
     */
    private void transform(Cipher cipher, ByteArrayInputStream toBeEncryptedInputStream, ByteArrayOutputStream encryptedOutputStream) throws IOException, IllegalBlockSizeException, BadPaddingException {
        CipherUtils.transform(cipher, toBeEncryptedInputStream, encryptedOutputStream, blockSize);
    }

}
