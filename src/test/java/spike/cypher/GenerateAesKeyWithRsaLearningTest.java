package spike.cypher;

import com.google.common.io.ByteStreams;
import com.google.common.io.Resources;
import com.google.common.primitives.Shorts;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

import static com.google.common.io.BaseEncoding.base64;
import static com.google.common.io.ByteStreams.readFully;
import static java.nio.charset.Charset.defaultCharset;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

public class GenerateAesKeyWithRsaLearningTest {

    private static final int PASSWORD_LENGTH = 10;
    private static final int ITERATION_ROUND = 5;
    private static final int DEFAULT_KEY_SIZE = 128;

    public static final String PROVIDER = "SunJCE";
    private static final int BLOCK_SIZE = 4 * 256;
    private static final int IV_LENGTH = 16;


    private Key privateKey;
    private Key publicKey;

    private RsaEncryptor rsa = new RsaEncryptor(PROVIDER, BLOCK_SIZE);
    private AesEncryptor aes = new AesEncryptor(PROVIDER, IV_LENGTH, BLOCK_SIZE);

    @Before
    public void setup() throws InvalidKeyException {
        // I don't why der is preferred over pem - -||
        privateKey = readKeyFromFile("private-rsa.der", true);
        publicKey = readKeyFromFile("public-rsa.der", false);
    }


    @Test
    public void shouldGenerateAesKeyWithRandomPasswordAndRsa() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException {
        String toBeEncrypted = "I'm supposed to be a file";
        String password = aRandomPassword();

        try (ByteArrayInputStream toBeEncryptedInputStream = new ByteArrayInputStream(toBeEncrypted.getBytes());
             ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream()) {

            appendPassword(password, encryptedOutputStream, publicKey);

            SecretKey aesKey = generateAesKey(password, DEFAULT_KEY_SIZE);

            aes.encrypt(aesKey, toBeEncryptedInputStream, encryptedOutputStream);

            try (ByteArrayInputStream encryptedInputStream = new ByteArrayInputStream(encryptedOutputStream.toByteArray())) {

                String decryptPassword = decryptPassword(encryptedInputStream, privateKey);

                assertThat(decryptPassword, equalTo(password));

                SecretKey shouldBeSameAesKey = generateAesKey(password, DEFAULT_KEY_SIZE);

                assertThat(Base64.getEncoder().encode(shouldBeSameAesKey.getEncoded()), equalTo(Base64.getEncoder().encode(aesKey.getEncoded())));

                ByteArrayOutputStream decryptedOutputStream = aes.decrypt(shouldBeSameAesKey, encryptedInputStream);

                assertThat(decryptedOutputStream.toString(), equalTo(toBeEncrypted));
            }
        }
    }

    private String aRandomPassword() {
        return UUID.randomUUID().toString().substring(0, PASSWORD_LENGTH);
    }

    private void appendPassword(String password, OutputStream outputStream, Key rsaPublicKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        ByteArrayOutputStream encryptedBytesStream = rsa.encrypt(rsaPublicKey, new ByteArrayInputStream(password.getBytes()));
        short length = (short) encryptedBytesStream.size();
        outputStream.write(Shorts.toByteArray(length));
        outputStream.write(encryptedBytesStream.toByteArray());
    }

    private String decryptPassword(InputStream inputStream, Key rsaKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        short passwordLength = getPasswordLength(inputStream);
        byte[] encryptedPassword = new byte[passwordLength];

        readFully(inputStream, encryptedPassword);
        ByteArrayOutputStream decryptedStream = rsa.decrypt(rsaKey, new ByteArrayInputStream(encryptedPassword));

        return new String(decryptedStream.toByteArray(), defaultCharset());
    }

    private short getPasswordLength(InputStream inputStream) throws IOException {
        byte[] header = new byte[2];
        readFully(inputStream, header);
        return Shorts.fromByteArray(header);
    }

    private static SecretKey generateAesKey(String password, int keySize) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] salt = base64().encode(password.getBytes(defaultCharset())).getBytes(defaultCharset());
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_ROUND, keySize);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private Key readKeyFromFile(String keyName, boolean isPrivateKey) throws InvalidKeyException {
        try (InputStream inputStream = Resources.asByteSource(Resources.getResource(keyName)).openStream()) {
            byte[] keyBytes = ByteStreams.toByteArray(inputStream);
            return generateRsaKey(keyBytes, isPrivateKey);
        } catch (IOException e) {
            throw new InvalidKeyException("Could not load key from file: " + keyName, e);
        }
    }

    private Key generateRsaKey(byte[] keyBytes, boolean isPrivateKey) throws InvalidKeyException {
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
}
