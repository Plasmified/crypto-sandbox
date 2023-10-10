import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.util.*;

public class GenerateKey {

/*****************************************************************
 Initializations
 Use proper parameterizarions
  note) Different symmetric algorithms use different keysizes ... 
 ****************************************************************/

  // public static final String ALGORITHM = "DESede";
  // public static final Integer KEYSIZE = 168;    // 64, 112 , 168  bits

  // public static final String ALGORITHM = "Blowfish";
  // public static final Integer KEYSIZE = 448;    // 64, 128, 256, 448 bits
  
  // You can select the right parameters for the key generation ...
  // according to the symmetric algorithm you want   

  public static final String ALGORITHM = "AES";
  public static final Integer KEYSIZE = 256;     // 128, 256 bits
  public static final String KEYRING = "keyring";
  
  private static String username = "Plasmified";
    

  /**
   * main()
   */
   
  public static String bytesToHex(byte[] bytes) {
	Formatter formatter = new Formatter();
	for (byte b : bytes) {
		formatter.format("%02x", b);
	}
	return formatter.toString();
   } 
   
  public static byte[] hexToBytes(String hex) {
	int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                             + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }
   
  public static SecretKey hexToSecretKey(String keyHex) {
    byte[] keyBytes = hexToBytes(keyHex);
    return new SecretKeySpec(keyBytes, "AES"); // Adjust the algorithm as needed
  }

  public static void main(String[] args) throws Exception {

    // Key generation for the chosen Alg. 

    KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
    kg.init(KEYSIZE);
    SecretKey key = kg.generateKey();
	
	KeyGenerator hmacKG = KeyGenerator.getInstance("HmacSHA256");
	SecretKey keyMac = hmacKG.generateKey();

    // We will store in a file (as a keyring, as a keystore file)
    // ... Good idea ? Better idea to store/manage the key more securely?

    OutputStream os = new FileOutputStream(KEYRING);
    try {
	  byte[] pureKey = key.getEncoded();
	  String keyHex = bytesToHex(pureKey);
	  String macKeyHex = bytesToHex(keyMac.getEncoded());
	  String keyNew = Base64.getEncoder().encodeToString(hexToSecretKey(keyHex).getEncoded());
	  
	  MessageDigest digest = MessageDigest.getInstance("SHA-256");
	  
	  byte[] inputBytes = username.getBytes();
	  
	  digest.update(inputBytes);
	  
	  byte[] hashBytes = digest.digest();
	  
	  String hashHex = bytesToHex(hashBytes);
	  
	  byte[] convertedBytes = hexToBytes(hashHex);
	  
	  boolean hashesMatch = MessageDigest.isEqual(hashBytes, convertedBytes);
	  
	  /*Mac mac = Mac.getInstance("HmacSHA256");
	  mac.init(keyMac);*/
	  
      //os.write(keyHex);
	  System.out.println();
      System.out.println("--------------------------------------------------------------------------------------------");
      System.out.println("Key " +ALGORITHM +" with "+KEYSIZE +" bits ");
	  System.out.println("Obtained Key in HEX : " + keyHex);
	  System.out.println("Obtained Key in Base64 format : " + keyNew);
	  System.out.println("Obtained Key in Byte Array format : " + pureKey.toString());
	  System.out.println("MAC Key : " + macKeyHex);
	  System.out.println("--------------------------------------------------------------------------------------------");
	  System.out.println("Hashed Username (in hex) : " + hashHex);
	  System.out.println("Original Hash : " + bytesToHex(hashBytes));
	  System.out.println("Converted to Bytes : " + bytesToHex(convertedBytes));
	  System.out.println("Hashes Match: " + hashesMatch);
      System.out.println("--------------------------------------------------------------------------------------------");
    } 
    finally {
      try {
        os.close();
      } catch (Exception e) {

        // ... Nothing by now ... Your exception handler if/when required

      } 
    } 
  } 

}









