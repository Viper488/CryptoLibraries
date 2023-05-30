package pk.hash;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256BC {
    public static String hashMethod1(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

        return new String(Hex.encode(hash));
    }

    public static String hashMethod2(String input) {
        byte[] inputByte = input.getBytes(StandardCharsets.UTF_8);
        Digest digest = new SHA256Digest();

        digest.reset();

        digest.update(inputByte, 0, inputByte.length);

        byte[] sha256Digest = new byte[digest.getDigestSize()];
        digest.doFinal(sha256Digest, 0);

        return new String(Hex.encode(sha256Digest));
    }
}
