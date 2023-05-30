package pk.sign;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.PublicKeySignFactory;
import com.google.crypto.tink.signature.PublicKeyVerifyFactory;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.signature.SignatureKeyTemplates;
import com.google.crypto.tink.subtle.Hex;

import java.nio.charset.StandardCharsets;
import java.security.*;
import io.vavr.control.Try;

public class TinkDsa {
    public static void sign(String input) throws GeneralSecurityException {
        System.out.println("ECDSA_P256");
        SignatureConfig.register();

        KeysetHandle key = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);

        PublicKeySign signer = PublicKeySignFactory.getPrimitive(key);
        byte[] signature = signer.sign(input.getBytes(StandardCharsets.UTF_8));

        System.out.println("Signature: " + Hex.encode(signature));

        PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(key.getPublicKeysetHandle());

        System.out.println("Is signature valid: " + Try.of(() -> {
            verifier.verify(signature, input.getBytes(StandardCharsets.UTF_8));
            return true;
        }).isSuccess());
    }

}
