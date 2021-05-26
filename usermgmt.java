

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.List;


//"zaštite koje su opisane na predavanju:" (to jos pogledat - Kontrola pristupa)

public class usermgmt {

    public static void main(String[] args) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        String ulaz;

        File file = new File("User_Manager.txt");
        if(!file.exists()){
            file.createNewFile();
        }

        if(args[0].equals("add")){
            //add user
            addUser(args[1]);
        } else if(args[0].equals("delete")){
            //delete user
            deleteUser(args[1]);
        } else if(args[0].equals("password")){
            //change password
            changePassword(args[1]);
        }else if(args[0].equals("forcePassword")){
            //force changing password
            forcePassword(args[1]);
        }else {
            System.out.println("Wrong input. Try again.");
        }

    }

    public static void addUser (String userName) throws NoSuchAlgorithmException,
            InvalidKeySpecException, IOException {
        //citanje passworda
        Console cons = System.console();
        String pass = String.valueOf(cons.readPassword("Password: "));
        String passRepeat = String.valueOf(cons.readPassword("Repeat password: "));
        if(!pass.equals(passRepeat)){
            System.out.println("User add failed. Password mismatch.\n");
        } else {
            //dodaj korisnika sa passwordom
            String finalString = hashPassword (userName, pass);
            //zapisi u datoteku
            FileWriter fw = new FileWriter(new File("").getAbsolutePath().concat("\\User_Manager.txt"), true);
            PrintWriter pw = new PrintWriter(fw);
            pw.println(finalString);
            pw.close();
            fw.close();
            System.out.println("User " + userName + " successfuly added.\n");
        }

    }

    public static void deleteUser (String userName) throws IOException {
        //izbrisi korisnika
        //pronadi di se nalazi taj user
        List<String> lines = Files.readAllLines(Path.of(new File("").getAbsolutePath().concat("\\User_Manager.txt")));
        int place = -1;
        for(int i = 0; i < lines.size(); i++){
            String[] line = lines.get(i).split("\\s+");
            if(line[0].equals(userName))
                place = i;
        }
        if(place < 0){
            System.out.println("It is not possible to delete user. User with "
                    + userName + " username already does not exist.\n");
        } else{
            FileWriter fw = new FileWriter(new File("").getAbsolutePath().concat("\\User_Manager.txt"));
            PrintWriter pw = new PrintWriter(fw);

            for(int i = 0; i <lines.size(); i++){
                if(i != place)
                   pw.println(lines.get(i));
            }
            pw.close();
            fw.close();

            System.out.println("User " + userName + " successfuly removed.\n");
        }

    }

    public static void changePassword (String userName) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        Console cons = System.console();
        String pass = String.valueOf(cons.readPassword("Password: "));
        String passRepeat = String.valueOf(cons.readPassword("Repeat password: "));
        if(!pass.equals(passRepeat)){
            System.out.println("Password change failed. Password mismatch.\n");
        } else{
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
                String finalString = hashPassword(userName, pass);
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

    public static void forcePassword (String userName) throws IOException {
        //narihtaj da mora promijenit pass
        //pronadi di se nalazi taj user
        List<String> lines = Files.readAllLines(Path.of(new File("").getAbsolutePath().concat("\\User_Manager.txt")));
        int place = -1;
        for(int i = 0; i < lines.size(); i++){
            String[] line = lines.get(i).split("\\s+");
            if(line[0].equals(userName))
                place = i;
        }
        if(place < 0){
            System.out.println("It is not possible to force user to change the password. User with "
                    + userName + " username does not exist.\n");
        } else{
            String finalString = lines.get(place);
            String helper = finalString.split("\\s+")[1];
            helper = " #?" + helper;
            finalString = finalString.split("\\s+")[0] + helper;
            lines.set(place, finalString);
            FileWriter fw = new FileWriter(new File("").getAbsolutePath().concat("\\User_Manager.txt"));
            PrintWriter pw = new PrintWriter(fw);

            for(String l : lines){
                pw.println(l);
            }
            pw.close();
            fw.close();

            System.out.println("User " + userName + " will be requested to change password on next login.\n");
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
