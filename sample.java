import java.io.IOException;
import java.util.Arrays;

public class Sample {
    public static void main(String[] args) throws IOException {
        String envPassword = System.getenv("APP_PASSWORD");
        char[] password = envPassword != null ? envPassword.toCharArray() : new char[0];
        try {
            // use password herem
        } finally {
            Arrays.fill(password, '\0');
        }

        if (args.length > 0) {
            new ProcessBuilder("ping", args[0]).start();
        }
    }
}
