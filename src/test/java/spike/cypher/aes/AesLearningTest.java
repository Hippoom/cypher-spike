package spike.cypher.aes;

import com.google.common.io.ByteStreams;
import org.junit.Test;

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
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class AesLearningTest {

    private static final int BLOCK_SIZE = 4 * 256;
    private static final int IV_LENGTH = 16;
    public static final String PROVIDER = "SunJCE";

    @Test
    public void shouldBeDecryptedWithTheSameKeyForEncryption()
            throws NoSuchPaddingException,
                   NoSuchAlgorithmException,
                   NoSuchProviderException,
                   InvalidAlgorithmParameterException,
                   InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        String toBeEncrypted = "This string is to be encrypted.";

        SecretKey secretKey = aRandomAesKey();

        try (ByteArrayInputStream toBeEncryptedInputStream = new ByteArrayInputStream(toBeEncrypted.getBytes())) {

            ByteArrayOutputStream encryptedOutputStream = encrypt(secretKey, toBeEncryptedInputStream);

            try (ByteArrayInputStream encryptedInputStream = new ByteArrayInputStream(encryptedOutputStream.toByteArray())) {

                ByteArrayOutputStream decryptedOutputStream = decrypt(secretKey, encryptedInputStream);

                assertThat(decryptedOutputStream.toString(), is(toBeEncrypted));
            }

        }
    }

    private ByteArrayOutputStream decrypt(SecretKey secretKey, ByteArrayInputStream encryptedInputStream) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        try (ByteArrayOutputStream decryptedOutputStream = new ByteArrayOutputStream()) {
            Cipher cipher = cipherForDecryption(secretKey, encryptedInputStream);

            transform(cipher, encryptedInputStream, decryptedOutputStream);
            return decryptedOutputStream;
        }
    }

    private Cipher cipherForDecryption(SecretKey secretKey, ByteArrayInputStream encryptedInputStream) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] ivInStream = fetchIvFromStream(encryptedInputStream);
        return cipher(PROVIDER, secretKey, Cipher.DECRYPT_MODE, new IvParameterSpec(ivInStream));
    }

    private byte[] fetchIvFromStream(ByteArrayInputStream encryptedInputStream) throws IOException {
        byte[] ivInStream = new byte[IV_LENGTH];
        ByteStreams.readFully(encryptedInputStream, ivInStream);
        return ivInStream;
    }

    private SecretKey aRandomAesKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // for example, it seems it requires additional jar to support 256 bit key
        return keyGen.generateKey();
    }

    private ByteArrayOutputStream encrypt(SecretKey secretKey, ByteArrayInputStream toBeEncryptedInputStream) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] iv = iDontKnowWhyIvIsGeneratedInThisWay(secretKey);
        Cipher cipher = cipher(PROVIDER, secretKey, ENCRYPT_MODE, new IvParameterSpec(iv));

        try (ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream()) {
            encryptedOutputStream.write(iv); // the beginning of the stream is IV?
            transform(cipher, toBeEncryptedInputStream, encryptedOutputStream);
            return encryptedOutputStream;
        }
    }

    private byte[] iDontKnowWhyIvIsGeneratedInThisWay(SecretKey secretKey) {
        return Arrays.copyOfRange(Base64.getEncoder().encode(secretKey.getEncoded()), 0, IV_LENGTH);
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
        byte[] buf = new byte[BLOCK_SIZE];

        int len;
        while ((len = ByteStreams.read(toBeEncryptedInputStream, buf, 0, BLOCK_SIZE)) == BLOCK_SIZE) {
            encryptedOutputStream.write(cipher.update(buf));
        }

        encryptedOutputStream.write(cipher.doFinal(buf, 0, len));
    }

}
