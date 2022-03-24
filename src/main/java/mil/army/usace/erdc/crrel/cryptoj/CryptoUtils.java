/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mil.army.usace.erdc.crrel.cryptoj;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author k3endrsg
 */
public class CryptoUtils {
    
    private static final int ivLength=16;
    
    public static String encryptAes256FromPassword(String data,String password){
        try{
            java.security.Security.addProvider(new BouncyCastleProvider());
            byte[] key = password.getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            key = sha.digest(key);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            byte[] pass1=encryptWithIv(data.getBytes(),secretKeySpec);
            return encrypt(pass1,secretKeySpec);
        }
        catch(Exception ex){
            throw new SecurityException("Unable to encrypt data",ex);
        }
    }
    
    public static String decryptAes256FromPassword(String data,String password){
        try{
            java.security.Security.addProvider(new BouncyCastleProvider());
            byte[] key = password.getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            key = sha.digest(key);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            byte[] dataWithIv = decrypt(data,secretKeySpec);
            byte[] decryptedData = decryptWithIv(dataWithIv,secretKeySpec);
            return new String(decryptedData);
        }
        catch(Exception ex){
            throw new SecurityException("Unable to decrypt data",ex);
        }
    }
    
    public static String encrypt(byte[] data, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = cipher.doFinal(data);
        return Base64.toBase64String(encVal);
    }
    
    public static byte[] decrypt(String base64EncryptedString, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodeVal = cipher.doFinal(Base64.decode(base64EncryptedString));
        return decodeVal;
    }
    
    
    public static byte[] encryptWithIv(byte[] data, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, InvalidAlgorithmParameterException, UnsupportedEncodingException{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = getIv();
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encVal = cipher.doFinal(data);
        byte[] encoded=new byte[iv.length+encVal.length];
        System.arraycopy(iv, 0, encoded, 0, iv.length);
        System.arraycopy(encVal,0 , encoded, iv.length, encVal.length);
        return encoded;
    }
    
    public static byte[] decryptWithIv(byte[] data, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        byte[] iv=Arrays.copyOfRange(data, 0, ivLength);
        byte[] encVal=Arrays.copyOfRange(data, ivLength, data.length);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decodeVal = cipher.doFinal(encVal);
        return decodeVal;
    }
    
    private static byte[] getIv(){
        byte[] iv = new byte[ivLength];
	SecureRandom prng = new SecureRandom();
        prng.nextBytes(iv);
        return iv;
    }
    
}
