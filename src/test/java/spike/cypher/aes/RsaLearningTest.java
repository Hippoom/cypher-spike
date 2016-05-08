package spike.cypher.aes;

import com.google.common.io.ByteStreams;
import com.google.common.io.Resources;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Command to generate keys using openssl:
 * <pre>
 * openssl genrsa -out private-rsa.pem 2048
 * openssl rsa -in private-rsa.pem -out public-rsa.pem -outform PEM -pubout
 * openssl rsa -in private-rsa.pem -pubout -outform DER -out public-rsa.der
 * openssl pkcs8 -topk8 -inform PEM -outform DER -in private-rsa.pem -out private-rsa.der -nocrypt
 *
 * openssl rsautl -decrypt -in /tmp/1374722674779-0/encrypted -inkey private-rsa.pem
 * </pre>
 */
public class RsaLearningTest {

    public static final String PROVIDER = "SunJCE";
    private static final int BLOCK_SIZE = 4 * 256;

    private Key privateKey;
    private Key publicKey;

    @Before
    public void setup() throws InvalidKeyException {
        // I don't why der is preferred over pem - -||
        privateKey = readKeyFromFile("private-rsa.der", true);
        publicKey = readKeyFromFile("public-rsa.der", false);
    }

    @Test
    public void shouldBeDecryptedWithTheSameKeyForEncryption() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        String toBeEncrypted = "This string is to be encrypted";

        try (ByteArrayInputStream toBeEncryptedInputStream = new ByteArrayInputStream(toBeEncrypted.getBytes())) {

            ByteArrayOutputStream encryptedOutputStream = encrypt(publicKey, toBeEncryptedInputStream);

            try (ByteArrayInputStream encryptedInputStream = new ByteArrayInputStream(encryptedOutputStream.toByteArray())) {

                ByteArrayOutputStream decryptedOutputStream = decrypt(privateKey, encryptedInputStream);

                assertThat(decryptedOutputStream.toString(), is(toBeEncrypted));
            }
        }
    }

    private Key readKeyFromFile(String keyName, boolean isPrivateKey) throws InvalidKeyException {
        try (InputStream inputStream = Resources.asByteSource(Resources.getResource(keyName)).openStream()) {
            byte[] keyBytes = ByteStreams.toByteArray(inputStream);
            return generateKey(keyBytes, isPrivateKey);
        } catch (IOException e) {
            throw new InvalidKeyException("Could not load key from file: " + keyName, e);
        }
    }

    private Key generateKey(byte[] keyBytes, boolean isPrivateKey) throws InvalidKeyException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            if (isPrivateKey) {
                return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            } else {
                return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
            }
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new InvalidKeyException("Could not load key: ", e);
        }
    }

    private ByteArrayOutputStream encrypt(Key publicKey, ByteArrayInputStream inputStream) throws IOException, NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            Cipher cipher = cipher(Cipher.ENCRYPT_MODE, publicKey);
            transform(cipher, inputStream, outputStream);

            return outputStream;
        }
    }

    private ByteArrayOutputStream decrypt(Key privateKey, ByteArrayInputStream inputStream) throws IOException, NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            Cipher cipher = cipher(Cipher.DECRYPT_MODE, privateKey);
            transform(cipher, inputStream, outputStream);

            return outputStream;
        }
    }

    private Cipher cipher(int mode, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", PROVIDER);
        cipher.init(mode, key);
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
