package pk;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import pk.asymetric.BcRsa;
import pk.hash.BcSha256;
import pk.hash.GuavaSha256;
import pk.sign.BcDsa;
import pk.sign.TinkDsa;
import pk.symmetric.BcSymmetric;
import pk.symmetric.TinkAes;

import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            String input = readFromFile();

            testBouncyCastle(input);

            testTink(input);
            testShaGuava(input);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void testBouncyCastle(String input) throws Exception {
        testSymmetricBouncyCastle("AES", input);
        testSymmetricBouncyCastle("Blowfish", input);
        testRsaBouncyCastle(input);
        testDsaBouncyCastle(input);
        testSHA256BouncyCastle(input);
    }

    public static void testTink(String input) throws Exception {
        testAesTink(input);
        testDsaTink(input);
        testShaGuava(input);
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
        BcSymmetric sym = new BcSymmetric(algorithm);

        byte[] ivBytes = BcSymmetric.generateIVBytes();
        String encrypted = sym.encrypt(input, ivBytes);
        String decrypted = sym.decrypt(encrypted, ivBytes);
        System.out.println(algorithm + "-CBC");
        showResult(input, encrypted, decrypted);
    }

    public static void testRsaBouncyCastle(String input) throws Exception {
        BcRsa rsa = new BcRsa(2048);
        String encrypted = rsa.encrypt(input);
        String decrypted = rsa.decrypt(encrypted);
        System.out.println("RSA");
        showResult(input, encrypted, decrypted);
    }
    public static void testDsaBouncyCastle(String input) {
        BcDsa dsa = new BcDsa();
        BigInteger[] signature = dsa.sign(input);
        boolean isValid = dsa.verify(input, signature);

        System.out.println("Signature: " + Hex.toHexString(Arrays.toString(signature).getBytes()));
        System.out.println("Signature is valid: " + isValid);
    }

    public static void testSHA256BouncyCastle(String input) throws NoSuchAlgorithmException {
        String hash1 = BcSha256.hashMethod1(input);
        String hash2 =  BcSha256.hashMethod2(input);
        System.out.println("Original text: " + input);
        System.out.println("Hash method 1: " + hash1);
        System.out.println("Hash method 2: " + hash2);
        System.out.println("Hash 1 " + (hash1.equals(hash2) ? "matches" : "doesn't match") + " hash 2");
    }

    public static void testAesTink(String input) throws GeneralSecurityException {
        TinkAes aes = new TinkAes();

        String encrypted = aes.encrypt(input);
        String decrypted = aes.decrypt(encrypted);
        System.out.println("AES");
        showResult(input, encrypted, decrypted);
    }

    public static void testDsaTink(String input) throws GeneralSecurityException {
        TinkDsa.sign(input);
    }
    public static void testShaGuava(String input) {
        String hash = GuavaSha256.hash(input);
        System.out.println("SHA256");
        System.out.println(hash);
    }

    private static void showResult(String input, String encrypted, String decrypted) {
        System.out.println("Original text: " + input);
        System.out.println("Encrypted text: " + encrypted);
        System.out.println("Decrypted text: " + decrypted);
        System.out.println("Decrypted text " + (input.equals(decrypted) ? "matches" : "doesn't match") + " original text");
    }
}
