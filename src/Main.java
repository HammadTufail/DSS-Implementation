import java.nio.file.*;
import java.io.*;
import java.util.*;
public class Main {

    public static void main(String[] args) throws Exception {

        System.out.println("Key Generation...");
        KeyGenerator kg = new KeyGenerator();
        kg.generateKey();
        args1="files/1000-length-page.txt"
        System.out.println("Key generated.");
        SigningAndVerification s = new SigningAndVerification();

        System.out.println("Signing...");
        String content = new Scanner(new File(args1)).useDelimiter("\\Z").next();
        MyBigInteger signature[] = s.sign(kg.getPrivateKey(), kg.getPublicKey(),content);
        System.out.println("Signed.");


		System.out.println("Press anykey to verify!)");
		Scanner scana = new Scanner(System.in);
		scana.next();
        String contentAgain = new Scanner(new File(args1)).useDelimiter("\\Z").next();
        System.out.println("Verifying...");
		if(s.verify(signature,contentAgain	, kg.getPublicKey()))
			System.out.println("Correct signature Found , data is not tampered");
		else
			System.out.println("Incorrect Signature , the data was tampered!");
        System.out.println("Verifying...");
    }
}