import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.List;
import java.util.Scanner;

public class PasswordManager {

    public static String masterPassword;
    public static byte[] salt = {-77, 36, 95, -99, -40, -9, 41, 117, -126, 7, 10, -97, 26, -127, -106, -61};
    public static byte[] ivBytes = {-111, 66, -28, -58, -94, 12, 86, -52, 69, -64, -124, -121, -100, 54, 48, 17};

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        Scanner s = new Scanner(System.in);
        String ulaz;


        File file = new File("Password_Manager.txt");
        if (file.createNewFile()) {
            System.out.println("Welcome to Password Manager.\n" +
                    "Please set your Master Password for Password Manager: ");
            masterPassword = s.nextLine();
            masPas(file);
        } else{
            System.out.println("Welcome to Password Manager.\n" +
                    "Please enter your Master Password: ");
            masterPassword = s.nextLine();

        }

        //tu se sad koristi pass manag sa svim ostalim zahtjevima
        while (s.hasNextLine() && !(ulaz = s.nextLine()).isEmpty()) {
            if(checkMasPas()) {
                String[] trenutniRed = ulaz.split("\\s+");
                if (trenutniRed[0].equals("init")) {
                    if (trenutniRed.length != 2)
                        System.out.println("Invalid command entry. Try again.");
                    else {
                        masterPassword = trenutniRed[1];
                        masPas(file);
                    }
                } else if (trenutniRed[0].equals("get")) {
                    if (trenutniRed.length != 2)
                        System.out.println("Invalid command entry. Try again.");
                    else
                        get(trenutniRed);
                } else if (trenutniRed[0].equals("put")) {
                    if (trenutniRed.length != 3)
                        System.out.println("Invalid command entry. Try again.");
                    else
                        put(trenutniRed);
                } else {
                    System.out.println("Invalid command entry. Try again.");
                }
            }else{
                System.out.println("Master password is incorrect. Try again.");
            }
        }
        s.close();
    }

    private static void masPas(File file) throws NoSuchAlgorithmException {
        MessageDigest mesDig = MessageDigest.getInstance("SHA-256");
        byte[] digest = null;

        try{
            byte[] masterArray = masterPassword.getBytes(StandardCharsets.UTF_8);
            mesDig.update(masterArray);
            digest = mesDig.digest();
        }catch(Exception e){
            e.printStackTrace();
        }

        try{
            String hexString = byteToString(digest);
            FileWriter fiWr = new FileWriter(file);
            PrintWriter prWr = new PrintWriter(fiWr);
            prWr.println(hexString);
            prWr.close();
            fiWr.close();

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static boolean checkMasPas() throws IOException, NoSuchAlgorithmException {
        List<String> lines = Files.readAllLines(Path.of(new File("").getAbsolutePath().concat("\\Password_Manager.txt")));
        String hash = lines.get(0);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = null;
        md.update(masterPassword.getBytes(StandardCharsets.UTF_8));
        digest = md.digest();
        String newHash = byteToString(digest);

        return newHash.equals(hash);
    }

    private static void put (String[] ulaz) {
        try{
            List<String> lines = Files.readAllLines(Path.of(new File("").getAbsolutePath().concat("\\Password_Manager.txt")));

            MessageDigest mesDig = MessageDigest.getInstance("SHA-256");
            byte[] byteAdr = ulaz[1].getBytes(StandardCharsets.UTF_8);
            byte[] digAdr = mesDig.digest(byteAdr);
            String hashAdr = byteToHex(digAdr);

            boolean upisana = false;
            int index = 0;
            for(int i = 1; i < lines.size(); i++){
                String adr = lines.get(i).split("\\s+")[0];
                if(adr.equals(hashAdr)){
                    upisana = true;
                    index = i;
                    break;
                }
            }

            StringBuilder sb = new StringBuilder();
            sb.append(ulaz[1]).append(masterPassword);

            KeySpec spec = new PBEKeySpec(sb.toString().toCharArray(), salt, 65536, 256);
            SecretKeyFactory scf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] key = scf.generateSecret(spec).getEncoded();
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, keySpec, iv);
            byte[] kriptat = c.doFinal(ulaz[2].getBytes(StandardCharsets.UTF_8));

            String stringKriptat = byteToHex(kriptat);

            if(upisana){
                lines.set(index, hashAdr + " " + stringKriptat);
                FileWriter fw = new FileWriter(new File("").getAbsolutePath().concat("\\Password_Manager.txt"));
                PrintWriter pw = new PrintWriter(fw);
                for(String l : lines)
                    pw.println(l);
                pw.close();
                fw.close();
                System.out.println("Password successfully updated.");

            }else{
                FileWriter fw = new FileWriter(new File("").getAbsolutePath().concat("\\Password_Manager.txt"), true);
                PrintWriter pw = new PrintWriter(fw);
                pw.println(hashAdr + " " + stringKriptat);
                pw.close();
                fw.close();
                System.out.println("Password successfully added.");
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static void get (String[] ulaz) {
        try{
            List<String> lines = Files.readAllLines(Path.of(new File("")
                        .getAbsolutePath().concat("\\Password_Manager.txt")));

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] byteAdresa = ulaz[1].getBytes(StandardCharsets.UTF_8);
            byte[] digestAdresa = md.digest(byteAdresa);
            String hashAdresa = byteToHex(digestAdresa);

            String line = null;
            for(String l : lines){
                String adr = l.split("\\s+")[0];
                if(adr.equals(hashAdresa)){
                    line = l;
                    break;
                }
            }

            if(line == null){
                System.out.println("There is no password for the given address.");
                return;
            }

            byte[] passBytes = hexToByte(line.split("\\s+")[1]);
            String mainKey = ulaz[1] + masterPassword;

            KeySpec spec = new PBEKeySpec(mainKey.toCharArray(), salt, 65536, 256);
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] key = f.generateSecret(spec).getEncoded();
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, keySpec, iv);

            c.update(passBytes);
            byte[] password = c.doFinal();
            String stringPassword = new String(password);

            System.out.println("Password for " + ulaz[1] + " is " + stringPassword);


        }catch(BadPaddingException e){
            System.out.println("Someone changed the original file.");
        }catch (Exception e){
            e.printStackTrace();
        }

    }

    private static String byteToString(byte[] array){
        StringBuffer hex = new StringBuffer();
        for(int i = 0; i < array.length; i++){
            hex.append(Integer.toHexString(0xFF & array[i]));
        }
        return hex.toString();
    }

    public static String byteToHex(byte[] bytearray) {
        if(bytearray.length == 0) return "";
        String s = "";
        for(int i = 0; i < bytearray.length; i++) {
            s += String.format("%02x", bytearray[i]);
        }
        return s;
    }

    private static byte[] hexToByte(String keytext) {
        if(keytext.length() % 2 != 0) throw new IllegalArgumentException();
        if(keytext.length() == 0) return new byte[0];
        byte[] data = new byte[keytext.length()/2];
        int ind = 0;
        while(ind < keytext.length()) {
            char x = keytext.charAt(ind);
            int value = 0;
            if(x >= 'A' && x <= 'F') {
                value = (10 + (x - 'A'));
            }else if(x >= 'a' && x <= 'f') {
                value = (10 + (x - 'a'));
            }else if(x >= '0' && x <= '9') {
                value = (x - '0');
            }else {
                throw new IllegalArgumentException("Illegal argument!");
            }
            data[ind/2] += (byte) (value << (((ind + 1) % 2) * 4));
            ind++;
        }
        return data;
    }



}
