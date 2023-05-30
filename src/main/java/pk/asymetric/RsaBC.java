package pk.asymetric;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class RsaBC {

    private final AsymmetricCipherKeyPair cipherKeyPair;
    private final RSAKeyParameters publicKey;
    private final RSAPrivateCrtKeyParameters privateKey;
    public RsaBC(int keySize) throws Exception {
        this.cipherKeyPair = generateRSAKeyPair(keySize);
        this.publicKey = (RSAKeyParameters) cipherKeyPair.getPublic();
        this.privateKey = (RSAPrivateCrtKeyParameters) cipherKeyPair.getPrivate();
    }

    private static AsymmetricCipherKeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(keySize);
        java.security.KeyPair keyPair = generator.generateKeyPair();
        AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(keyPair.getPublic().getEncoded());
        AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    public String encrypt(String data) {
        byte[] byteData = data.getBytes(StandardCharsets.UTF_8);
        RSAEngine rsaEngine = new RSAEngine();
        rsaEngine.init(true, this.publicKey);
        return Base64.getEncoder().encodeToString(rsaEngine.processBlock(byteData, 0, byteData.length));
    }

    public String decrypt(String ciphertext) {
        byte[] cipherByte = Base64.getDecoder().decode(ciphertext);
        RSAEngine rsaEngine = new RSAEngine();
        rsaEngine.init(false, this.privateKey);

        return new String(rsaEngine.processBlock(cipherByte, 0, cipherByte.length), StandardCharsets.UTF_8);
    }
}
