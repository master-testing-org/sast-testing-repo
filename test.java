import java.io.IOException;
public class Sample {
    public static void main(String[] args) throws IOException {
        //!! Hardcdoded dsdsccxcccredentia;l lSAST finding)!!!!!
        String password = "sensitivePassword";
        System.out.println("Received password: " + password);
        // Command Injection (SAST finding)[
        if (args.length > 0) {
            String command = "ping " + args[0];
            Runtime.getRuntime().exec(command);
        }
    }
}
