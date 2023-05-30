package pk.hash;

import java.nio.charset.StandardCharsets;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;

public class GuavaSha256 {
    public static String hash(String input) {
        HashCode hashCode = Hashing.sha256().hashString(input, StandardCharsets.UTF_8);
        return hashCode.toString();
    }
}
