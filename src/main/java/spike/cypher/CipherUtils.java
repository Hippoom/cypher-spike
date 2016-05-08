package spike.cypher;

import com.google.common.io.ByteStreams;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public final class CipherUtils {
    private CipherUtils() {
    }

    /**
     * Streams is preferred for parameters so that it will be easier to support {@link java.io.File} after
     */
    public static void transform(Cipher cipher, ByteArrayInputStream toBeEncryptedInputStream, ByteArrayOutputStream encryptedOutputStream, int blockSize) throws IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] buf = new byte[blockSize];

        int len;
        while ((len = ByteStreams.read(toBeEncryptedInputStream, buf, 0, blockSize)) == blockSize) {
            encryptedOutputStream.write(cipher.update(buf));
        }

        encryptedOutputStream.write(cipher.doFinal(buf, 0, len));
    }
}
