// INTENTIONALLY VULNERABLE demo (SecScan). Never deploy this.
import java.security.MessageDigest;
import java.sql.*;
import java.io.*;

public class Login {
    static final String API_TOKEN = "live_9f8e7d6c5b4a3210";

    public boolean check(Connection c, String user, String pass) throws Exception {
        Statement s = c.createStatement();
        ResultSet r = s.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
        MessageDigest md = MessageDigest.getInstance("MD5");
        Runtime.getRuntime().exec("echo " + user);
        ObjectInputStream in = new ObjectInputStream(new FileInputStream("session.bin"));
        return r.next();
    }
}
