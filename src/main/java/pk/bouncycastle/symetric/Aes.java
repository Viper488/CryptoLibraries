package pk.bouncycastle.symetric;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class Aes {
    private final int KEY_SIZE = 256;
    private static final int IV_SIZE = 16;
    private final SecretKey secretKey;
    private final BufferedBlockCipher cipher;

    public Aes() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleProvider());
        this.secretKey = generateKey();
        this.cipher = initializeCypher();
    }

    private SecretKey generateKey() throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(KEY_SIZE);

        return keyGenerator.generateKey();
    }

    private PaddedBufferedBlockCipher initializeCypher() {
        return new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
    }

    public byte[] encrypt(String data, byte[] ivBytes) throws InvalidCipherTextException {
        byte[] input = data.getBytes(StandardCharsets.UTF_8);

        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(this.secretKey.getEncoded()), ivBytes);
        cipher.init(true, parameters);


        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int outputLength = cipher.processBytes(input, 0, input.length, output, 0);
        cipher.doFinal(output, outputLength);

        return output;
    }

    public byte[] decrypt(byte[] cipherText, byte[] ivBytes) throws InvalidCipherTextException {
        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(this.secretKey.getEncoded()), ivBytes);
        cipher.init(false, parameters);
        byte[] output = new byte[cipher.getOutputSize(cipherText.length)];
        int outputLength = cipher.processBytes(cipherText, 0, cipherText.length, output, 0);
        outputLength += cipher.doFinal(output, outputLength);

        return Arrays.copyOf(output, outputLength);
    }

    public static byte[] generateIVBytes() {
        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[IV_SIZE];
        random.nextBytes(ivBytes);

        return ivBytes;
    }

    public static String printEncrypted(byte[] encrypted) {
        return Hex.toHexString(encrypted);
    }

    public static String printDecrypted(byte[] decrypted) {
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
