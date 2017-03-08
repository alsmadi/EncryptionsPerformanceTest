import java.util.Scanner;
import java.util.Random;
import java.util.ArrayList;

import java.security.Security;
import java.security.SecureRandom;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Signature;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.SignatureException;

import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class CryptoTests {

	public static void performTest(String algorithm, byte[] byteInput, boolean print) {

		if(print) {
			System.out.println("Performing " + algorithm + " on input.");
		}

		if(algorithm.equals("AES") || algorithm.equals("Blowfish")) {
			try {
				// Generate secret key
				KeyGenerator keyGen = KeyGenerator.getInstance(algorithm, "BC");
				keyGen.init(128, new SecureRandom());
				Key key = keyGen.generateKey();

				// Specify and intalize cipher to encrypt
				Cipher cipher = Cipher.getInstance(algorithm);
				cipher.init(Cipher.ENCRYPT_MODE, key);

				// Perform encryption on byte input
				byte[] encryptedBytes = cipher.doFinal(byteInput);

				// Intialize decrypt mode
				cipher.init(Cipher.DECRYPT_MODE, key);

				// Perform decryption of encrypted input
				byte[] outputBytes = cipher.doFinal(encryptedBytes);

				// Convert bytes to string
				String output = new String(outputBytes);

				if(print) {
					System.out.println("Output: " + output + "\n");
				}

			} catch (NoSuchAlgorithmException e) {
				System.out.println("Error: NoSuchAlgorithmException");
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				System.out.println("Error: NoSuchProviderException");
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				System.out.println("Error: NoSuchPaddingException");
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				System.out.println("Error: InvalidKeyException");
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				System.out.println("Error: IllegalBlockSizeException");
				e.printStackTrace();
			} catch (BadPaddingException e) {
				System.out.println("Error: BadPaddingException");
				e.printStackTrace();
			}
		} else if (algorithm.equals("RSA")) {
			try {
				// Intializse key pair generator
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm, "BC");
				keyGen.initialize(128, new SecureRandom());

				// Generate public / private key pair
				KeyPair pair = keyGen.generateKeyPair();
				PrivateKey privKey = pair.getPrivate();
				PublicKey pubKey = pair.getPublic();

				// Intialize RSA signature, update signature to byte input, get signature bytes
				Signature sig = Signature.getInstance("RSA", "BC");
				byte[] byteSignature = {};
				if(byteInput.length < 6) {	// can't generate signatures larger than 5 bytes?
					sig.initSign(privKey);
					sig.update(byteInput);
					byteSignature = sig.sign();
				}

				// Specify and intalize cipher to encrypt with public key
				Cipher cipher = Cipher.getInstance(algorithm);
				cipher.init(Cipher.ENCRYPT_MODE, pubKey);

				// Perform encryption on byte input
				byte[] encryptedBytes = cipher.doFinal(byteInput);

				// Intialize decrypt mode with private key
				cipher.init(Cipher.DECRYPT_MODE, privKey);

				// Perform decryption of encrypted input
				byte[] outputBytes = cipher.doFinal(encryptedBytes);

				// Convert bytes to string
				String output = new String(outputBytes);

				// Intialize signature varification
				sig.initVerify(pubKey);
				sig.update(byteInput);

				if(print) {
					System.out.println("Output: " + output);
				}

				// Verify signature
				if(byteInput.length < 6 && sig.verify(byteSignature)) {	// can't generate signatures larger than 5 bytes?
					if(print) {
						System.out.println("Signature Verification Successful.\n");
					}
				} else {
					if(print) {
						System.out.println("Signature Verification Unsuccessful.\n");
					}
				}

			} catch (NoSuchAlgorithmException e) {
				System.out.println("Error: NoSuchAlgorithmException");
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				System.out.println("Error: NoSuchProviderException");
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				System.out.println("Error: NoSuchPaddingException");
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				System.out.println("Error: InvalidKeyException");
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				System.out.println("Error: IllegalBlockSizeException");
				e.printStackTrace();
			} catch (BadPaddingException e) {
				System.out.println("Error: BadPaddingException");
				e.printStackTrace();
			} catch (SignatureException e) {
				System.out.println("Error: SignatureException");
				e.printStackTrace();
			}
		} else {
			System.out.println("Error: Invalid algorithm.");
		}
	}

	public static String generateRandomString() {
		
		Random random = new Random();
		int strLen = 4 + random.nextInt(6);	//random string between length 4 and 10

		char[] randomCharArr = new char[strLen];

		for(int i = 0; i < strLen; i++) {
			char randChar = (char) (48 + random.nextInt(122));	//generate ASCII characters between 48 and 122
			randomCharArr[i] = randChar;
		}

		return new String(randomCharArr);

	}

	public static long iterateAndTest(ArrayList<String> randomStringList, String algorithm) {

		long start = 0;
		long end = 0;
		long timeElapsed = 0;

		start = System.nanoTime();

		for(int i = 0; i < randomStringList.size(); i++) {
			performTest(algorithm, randomStringList.get(i).getBytes(), false);
		}

		end = System.nanoTime();

		timeElapsed = (end - start) / 1000000;	//time in milliseconds

		return timeElapsed;

	}

	public static void performTestOnRandomStrings() {

		ArrayList<String> randomStringList = new ArrayList<String>(100);

		for(int i = 0; i < 100; i++) {
			randomStringList.add(generateRandomString());
		}

		System.out.println("TESTING ALGORITHMS ON RANDOM STRINGS\n");

		// These are not included in the test of random strings, using each algorithm once before test speeds up performance
		performTest("AES", "AES".getBytes(), false);
		performTest("Blowfish", "Blowfish".getBytes(), false);
		performTest("RSA", "RSA".getBytes(), false);

		long aesTime = iterateAndTest(randomStringList, "AES");
		long blowfishTime = iterateAndTest(randomStringList, "Blowfish");
		long rsaTime = iterateAndTest(randomStringList, "RSA");

		System.out.println("Time to encrypt 100 random strings with AES: " + aesTime + "ms");
		System.out.println("Time to encrypt 100 random strings with Blowfish: " + blowfishTime + "ms");
		System.out.println("Time to encrypt 100 random strings with RSA: " + rsaTime + "ms");

		System.out.println();

		System.out.println("AES is " + (rsaTime / aesTime) + " times faster than RSA.");
		System.out.println("Blowfish is " + (rsaTime / blowfishTime) + " times faster than RSA.");
		System.out.println("Blowfish is " + (aesTime / blowfishTime) + " times faster than AES.");
	}
        
        public static void performTestOnRandomStrings(int N) {

		ArrayList<String> randomStringList = new ArrayList<String>(N);

		for(int i = 0; i < N; i++) {
			randomStringList.add(generateRandomString());
		}

		System.out.println("TESTING ALGORITHMS ON RANDOM STRINGS\n");

		// These are not included in the test of random strings, using each algorithm once before test speeds up performance
		performTest("AES", "AES".getBytes(), false);
		performTest("Blowfish", "Blowfish".getBytes(), false);
		performTest("RSA", "RSA".getBytes(), false);

		long aesTime = iterateAndTest(randomStringList, "AES");
		long blowfishTime = iterateAndTest(randomStringList, "Blowfish");
		long rsaTime = iterateAndTest(randomStringList, "RSA");

		System.out.println("Time to encrypt "+N+"random strings with AES: " + aesTime + "ms");
		System.out.println("Time to encrypt "+N+" random strings with Blowfish: " + blowfishTime + "ms");
		System.out.println("Time to encrypt "+N+" random strings with RSA: " + rsaTime + "ms");

		System.out.println();

		System.out.println("AES is " + (rsaTime / aesTime) + " times faster than RSA.");
		System.out.println("Blowfish is " + (rsaTime / blowfishTime) + " times faster than RSA.");
		System.out.println("Blowfish is " + (aesTime / blowfishTime) + " times faster than AES.");
	}

	public static void main(String[] args) {
		// Add BouncyCastle Provider
		Security.addProvider(new BouncyCastleProvider());

		// Read user input
		Scanner scanner = new Scanner(System.in);
		System.out.print("\nDo you want to test user (i)nput or generate (r)andom 100 chars string?, (x) random N chars in the string ");
		char option = Character.toLowerCase(scanner.nextLine().charAt(0));
                 System.out.println(option);
		if(option == 'i') {
			System.out.print("\nPlease enter a string you would like to encrypt: ");
			String input = scanner.nextLine();
			scanner.close();

			System.out.println();

			// Get input bytes
			byte[] byteInput = input.getBytes();

			performTest("AES", byteInput, true);
			performTest("Blowfish", byteInput, true);
			performTest("RSA", byteInput, true);
		}
                else if (option == 'x') {
                    System.out.print("test");
                    System.out.print("\nPlease enter the number of chars in random string: ");
		//	String input = scanner.nextLine();
                        Scanner sc = new Scanner(System.in);
                 int num1=0;
                while (!sc.hasNextInt()) sc.next();{
                 num1 = sc.nextInt();
                }
                scanner.close();
			//scanner.close();
			
			System.out.println();
                      
			performTestOnRandomStrings(num1);
		}
                else if (option == 'r') {
			scanner.close();
			System.out.println();
			performTestOnRandomStrings();
		}
                

	}

}