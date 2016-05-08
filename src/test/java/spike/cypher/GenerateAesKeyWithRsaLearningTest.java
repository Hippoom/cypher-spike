package spike.cypher;

import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.UUID;

import static com.google.common.io.BaseEncoding.base64;
import static java.nio.charset.Charset.defaultCharset;

public class GenerateAesKeyWithRsaLearningTest {

    private static final int PASSWORD_LENGTH = 10;
    private static final int ITERATION_ROUND = 5;
    private static final int DEFAULT_KEY_SIZE = 128;


    @Test
    public void shouldGenerateAesKeyWithRandomPasswordAndRsa() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String password = UUID.randomUUID().toString().substring(0, PASSWORD_LENGTH);



        SecretKey secretKey = generateKey(password, DEFAULT_KEY_SIZE);


    }


    private static SecretKey generateKey(String password, int keySize) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] salt = base64().encode(password.getBytes(defaultCharset())).getBytes(defaultCharset());
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_ROUND, keySize);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }



}
