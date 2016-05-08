package spike.cypher;

import org.junit.Test;

import javax.crypto.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * For IV, check here:http://security.stackexchange.com/questions/35210/encrypting-using-aes-256-do-i-need-iv
 */
public class AesLearningTest {

    private static final int BLOCK_SIZE = 4 * 256;
    private static final int IV_LENGTH = 16;
    public static final String PROVIDER = "SunJCE";

    private AesEncryptor subject = new AesEncryptor(PROVIDER, IV_LENGTH, BLOCK_SIZE);

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

            ByteArrayOutputStream encryptedOutputStream = subject.encrypt(secretKey, toBeEncryptedInputStream);

            try (ByteArrayInputStream encryptedInputStream = new ByteArrayInputStream(encryptedOutputStream.toByteArray())) {

                ByteArrayOutputStream decryptedOutputStream = subject.decrypt(secretKey, encryptedInputStream);

                assertThat(decryptedOutputStream.toString(), is(toBeEncrypted));
            }

        }
    }

    private SecretKey aRandomAesKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // for example, it seems it requires additional jar to support 256 bit key
        return keyGen.generateKey();
    }


}
