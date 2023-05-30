package pk.sign;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class BcDsa {

    private final DSAPublicKeyParameters publicKey;
    private final DSAPrivateKeyParameters privateKey;

    public BcDsa() {
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        this.publicKey = (DSAPublicKeyParameters) keyPair.getPublic();
        this.privateKey = (DSAPrivateKeyParameters) keyPair.getPrivate();
    }

    private static AsymmetricCipherKeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();

        DSAParametersGenerator parametersGenerator = new DSAParametersGenerator();
        parametersGenerator.init(2048, 256, random);
        DSAParameters parameters = parametersGenerator.generateParameters();

        DSAKeyGenerationParameters keyGenerationParameters = new DSAKeyGenerationParameters(random, parameters);

        DSAKeyPairGenerator keyPairGenerator = new DSAKeyPairGenerator();
        keyPairGenerator.init(keyGenerationParameters);

        return keyPairGenerator.generateKeyPair();
    }

    public BigInteger[] sign(String data) {
        DSASigner signer = new DSASigner(new RandomDSAKCalculator());

        signer.init(true, this.privateKey);

        return signer.generateSignature(data.getBytes(StandardCharsets.UTF_8));
    }


    public boolean verify(String data, BigInteger[] signature) {
        DSASigner signer = new DSASigner();

        signer.init(false, this.publicKey);

        return signer.verifySignature(data.getBytes(StandardCharsets.UTF_8), signature[0], signature[1]);
    }
}
