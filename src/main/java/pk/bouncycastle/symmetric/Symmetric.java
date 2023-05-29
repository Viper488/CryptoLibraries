package pk.bouncycastle.symmetric;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class Symmetric {
    private final int KEY_SIZE = 256;
    private static final int IV_SIZE = 16;
    private SecretKey secretKey;
    private PaddedBufferedBlockCipher cipher;

    public Symmetric(String algorithm) throws GeneralSecurityException {
        if (algorithm.equals("AES")) {
            initializeAes();
        } else if (algorithm.equals("Blowfish")){
            initializeBlowfish();
        } else {
            throw new RuntimeException("Algorithm " + algorithm + " not available!");
        }
    }

    private void initializeAes() throws NoSuchAlgorithmException, NoSuchProviderException {
        AESEngine engine = new AESEngine();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(engine.getAlgorithmName(), "BC");
        keyGenerator.init(KEY_SIZE);
        this.secretKey = keyGenerator.generateKey();
        this.cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
    }

    private void initializeBlowfish() throws NoSuchAlgorithmException, NoSuchProviderException {
        BlowfishEngine engine = new BlowfishEngine();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(engine.getAlgorithmName(), "BC");
        keyGenerator.init(KEY_SIZE);
        this.secretKey = keyGenerator.generateKey();
        this.cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
    }

    public String encrypt(String data, byte[] ivBytes) throws InvalidCipherTextException {
        byte[] input = data.getBytes(StandardCharsets.UTF_8);

        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(this.secretKey.getEncoded()), ivBytes);
        cipher.init(true, parameters);

        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int outputLength = cipher.processBytes(input, 0, input.length, output, 0);
        cipher.doFinal(output, outputLength);

        return Base64.getEncoder().encodeToString(output);
    }

    public String decrypt(String cipherText, byte[] ivBytes) throws InvalidCipherTextException {
        byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(this.secretKey.getEncoded()), ivBytes);
        cipher.init(false, parameters);
        byte[] output = new byte[cipher.getOutputSize(cipherBytes.length)];
        int outputLength = cipher.processBytes(cipherBytes, 0, cipherBytes.length, output, 0);
        outputLength += cipher.doFinal(output, outputLength);

        return new String(Arrays.copyOf(output, outputLength), StandardCharsets.UTF_8);
    }

    public static byte[] generateIVBytes() {
        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[IV_SIZE];
        random.nextBytes(ivBytes);

        return ivBytes;
    }
}
