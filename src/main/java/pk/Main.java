package pk;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import pk.bouncycastle.asymetric.Rsa;
import pk.bouncycastle.sign.Dsa;
import pk.bouncycastle.symmetric.Symmetric;
import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            String input = readFromFile();
            testSymmetricBouncyCastle("AES", input);
            testSymmetricBouncyCastle("Blowfish", input);
            testRsaBouncyCastle(input);
            testDsaBouncyCastle(input);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String readFromFile() throws FileNotFoundException {
        StringBuilder sb = new StringBuilder();
        File file = new File("./src/main/resources/plaintext.txt");
        Scanner myReader = new Scanner(file);

        while (myReader.hasNextLine()) {
            sb.append(myReader.nextLine());
        }
        myReader.close();

        return sb.toString();
    }

    public static void testSymmetricBouncyCastle(String algorithm, String input) throws GeneralSecurityException, InvalidCipherTextException {
        Symmetric sym = new Symmetric(algorithm);

        byte[] ivBytes = Symmetric.generateIVBytes();
        String encrypted = sym.encrypt(input, ivBytes);
        String decrypted = sym.decrypt(encrypted, ivBytes);
        System.out.println(algorithm + "-CBC");
        showResult(input, encrypted, decrypted);
    }

    public static void testRsaBouncyCastle(String input) throws Exception {
        Rsa rsa = new Rsa(2048);
        String encrypted = rsa.encrypt(input);
        String decrypted = rsa.decrypt(encrypted);
        System.out.println("RSA");
        showResult(input, encrypted, decrypted);
    }
    public static void testDsaBouncyCastle(String input) {
        Dsa dsa = new Dsa();
        BigInteger[] signature = dsa.sign(input);
        boolean isValid = dsa.verify(input, signature);

        System.out.println("Signature: " + Hex.toHexString(Arrays.toString(signature).getBytes()));
        System.out.println("Signature is valid: " + isValid);
    }

    private static void showResult(String input, String encrypted, String decrypted) {
        System.out.println("Original text: " + input);
        System.out.println("Encrypted text: " + encrypted);
        System.out.println("Decrypted text: " + decrypted);
        System.out.println("Decrypted text " + (input.equals(decrypted) ? "matches" : "doesn't match") + " original text");
    }
}
