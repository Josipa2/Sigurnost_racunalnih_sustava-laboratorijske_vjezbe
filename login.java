
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class login {

    public static List<String> lines = new ArrayList<>();

    public static void main(String[] args) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        lines = Files.readAllLines(Path.of(new File("").getAbsolutePath().concat("\\User_Manager.txt")));

        String userName = args[0];
        //nema opcija, treba loginat korisnika i po potrebi mozda natjerat da promijeni lozinku
        //ucitavanje lozinke korisnika
        Console cons = System.console();
        String pass = String.valueOf(cons.readPassword("Password: "));

//        String pass = "test";

        int place = -1;
        for(int i = 0; i < lines.size(); i++){
            String[] line = lines.get(i).split("\\s+");
            if(line[0].equals(userName))
                place = i;
        }
        if(place < 0){
            System.out.println("Username or password incorrect.\n");
            return;
        } else{
            String password = lines.get(place).split("\\s+")[1];
            if (password.startsWith("#?")){
                //check if password is correct
                password = password.substring(2);
                if(passwordCheck(password, pass, place)){
                    System.out.println("Username or password incorrect.");
                }else{
                    forcedChangeOfPass(userName);
                }
            } else{
                //check if password is correct
                if(passwordCheck(password, pass, place)){
                    System.out.println("Username or password incorrect.");
                }else{
                    System.out.println("Login successful.\n" + "Welcome " + userName);
                }
            }
        }

    }

    public static boolean passwordCheck(String password, String pass, int place) throws
             NoSuchAlgorithmException, InvalidKeySpecException {
        if(place < 0){
            return false;
        } else{
            byte[] bytePFF = password.getBytes(StandardCharsets.UTF_8);
            byte[] salt = new byte[16];
            byte[] bytePass = new byte[bytePFF.length - 16];
            for(int i = 0; i < 16; i++){
                salt[i] = bytePFF[i];
            }
            for(int i = 16, j = 0; i < bytePFF.length; i++, j++){
                bytePass[j] = bytePFF[i];
            }

            KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, 65536, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Arrays.equals(bytePass,hash);
        }
    }

    public static void forcedChangeOfPass (String userName) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        Console cons = System.console();
        String newPass = String.valueOf(cons.readPassword("New password: "));
        String newPassRepeat = String.valueOf(cons.readPassword("Repeat new password: "));
        if(!newPass.equals(newPassRepeat)){
            System.out.println("Login unsuccessful. Password mismatch.\n");
        } else{
            //promijeni lozinku korisniku

            //pronadi di se nalazi taj user
            List<String> lines = Files.readAllLines(Path.of(new File("").getAbsolutePath().concat("\\User_Manager.txt")));
            int place = -1;
            for(int i = 0; i < lines.size(); i++){
                String[] line = lines.get(i).split("\\s+");
                if(line[0].equals(userName))
                    place = i;
            }
            if(place < 0){
                System.out.println("It is not possible to change the password. User with "
                        + userName + " username does not exist.\n");
            } else{
                String finalString = hashPassword(userName, newPass);
                lines.set(place, finalString);
                FileWriter fw = new FileWriter(new File("").getAbsolutePath().concat("\\User_Manager.txt"));
                PrintWriter pw = new PrintWriter(fw);

                for(String l : lines){
                    pw.println(l);
                }
                pw.close();
                fw.close();

                System.out.println("Successful password change for " + userName + ".\n");
            }
        }
    }

    public static String hashPassword(String userName, String pass) throws InvalidKeySpecException,
            NoSuchAlgorithmException, IOException {

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        byte[] hash = factory.generateSecret(spec).getEncoded();

        byte[] finalHash = new byte[salt.length + hash.length];
        for (int i = 0; i < finalHash.length; ++i) {
            finalHash[i] = i < salt.length ? salt[i] : hash[i - hash.length];
        }

        String finalString = userName + " ";

        for(int i = 0; i < finalHash.length; i++) {
            finalString += String.format("%02x", finalHash[i]);
        }

        return finalString;

    }

}
