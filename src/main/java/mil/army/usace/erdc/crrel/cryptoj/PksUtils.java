/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mil.army.usace.erdc.crrel.cryptoj;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 *
 * @author U4RRCRSG
 */
public class PksUtils {
    
    public enum CertificateFormat{
        DER,
        PEM
    }
    
    public static X509Certificate getCert(String keyFilePath, String password, String keyAlias, String keyStoreType) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException{
       KeyStore ks = KeyStore.getInstance(keyStoreType);
        char[] pwd= password.toCharArray();
        try(java.io.FileInputStream fis = new java.io.FileInputStream(keyFilePath)){
            ks.load(fis, pwd);
            return (X509Certificate)ks.getCertificate(keyAlias);
        } 
    }
    
    public static X509Certificate getCertFromPEM(String pem,boolean fromApacheHeader) throws IOException{
        ///////////////
        if(fromApacheHeader){
            pem = "-----BEGIN CERTIFICATE-----\n"+pem.substring(28,pem.length()-25)+"\n-----END CERTIFICATE-----";
        }
        Reader reader = new StringReader(pem);
        PemReader pemReader = new PemReader(reader);
        PemObject pemObject = pemReader.readPemObject();
        return getCertFromPEM(pemObject);
    }
    
    public static X509Certificate getCertFromPEM(PemObject po){
        try{         
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(new ByteArrayInputStream(po.getContent()));
            if(cert instanceof X509Certificate)
                return (X509Certificate)cert;
            else
                throw new SecurityException("Invalid Certificate Type");
        }
        catch(CertificateException ex){
            throw new SecurityException("Invalid Certificate Format");
        }
    }
    
    public static PrivateKey readPrivateKey(String keyFile,CertificateFormat format){
        try{
            byte[] keyBytes;
            switch(format){
                case PEM:
                    String pem=new String(Files.readAllBytes(Paths.get(keyFile)));
                    String privKeyPEM = pem.replace("-----BEGIN PRIVATE KEY-----\n", "");
                    privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
                    Base64 b64 = new Base64();
                    keyBytes = b64.decode(privKeyPEM);
                    break;
                case DER:
                    keyBytes=Files.readAllBytes(Paths.get(keyFile));
                    break;
                default:
                    throw new RuntimeException("Invalid Key Format");
            }
            return readPrivateKey(keyBytes);
        }
        catch(IOException ex){
            throw new SecurityException("Unable to read file: "+ex.getMessage(),ex);
        }
        
    }
    
    //pem string format
    public static PrivateKey readPrivateKey(String pemString){
       Base64 b64 = new Base64();
       byte[] keyBytes = b64.decode(pemString);
       return readPrivateKey(keyBytes);       
    }
    
    //decoded format
    public static PrivateKey readPrivateKey(byte[] keyBytes){
        try{
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException ex){
            throw new SecurityException("Invalid Certificate Format or Specification: "+ex.getMessage(),ex);
        }
    }
    
    public static PublicKey readPublicKey(String keyFile,CertificateFormat format){
        try{
            byte[] keyBytes;
            switch(format){
                case PEM:
                    String pem=new String(Files.readAllBytes(Paths.get(keyFile)));
                    String pubKeyPEM = pem.replace("-----BEGIN PUBLIC KEY-----\n", "");
                    pubKeyPEM = pubKeyPEM.replace("-----END PUBLIC KEY-----", "");
                    Base64 b64 = new Base64();
                    keyBytes = b64.decode(pubKeyPEM);
                    break;
                case DER:
                    keyBytes=Files.readAllBytes(Paths.get(keyFile));
                    break;
                default:
                    throw new RuntimeException("Invalid Key Format");
            }
            return readPublicKey(keyBytes);
        }
        catch(IOException ex){
            throw new SecurityException("Unable to read file: "+ex.getMessage(),ex);
        }
    }
    
    public static PublicKey readPublicKey(byte[] keyBytes){
        try{
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException ex){
            throw new SecurityException("Invalid Certificate Format or Specification: "+ex.getMessage(),ex);
        }
    }
    
    
    public static PublicKey readPublicKey(String pemString){
        Base64 b64 = new Base64();
        byte[] keyBytes = b64.decode(pemString);
        return readPublicKey(keyBytes); 
    }
    
    //PEM Public Key format
    /*
    public static PublicKey readPublicKeyFromPemFile(String pemFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{

        byte[] keyBytes = Files.readAllBytes(Paths.get(pemFile));
        String temp = new String(keyBytes);
        String publicKeyPEM = temp.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
        BASE64Decoder b64=new BASE64Decoder();
        byte[] decoded = b64.decodeBuffer(publicKeyPEM);
        X509EncodedKeySpec spec =new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA"); // Assuming this is an RSA key
        PublicKey rsaPubKey = (PublicKey) kf.generatePublic(spec);
        return rsaPubKey;
    }
    
    public static PublicKey readPublicKeyFromPem(String pem) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        BASE64Decoder b64=new BASE64Decoder();
        byte[] decoded = b64.decodeBuffer(pem);
        X509EncodedKeySpec spec =new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA"); // Assuming this is an RSA key
        PublicKey rsaPubKey = (PublicKey) kf.generatePublic(spec);
        return rsaPubKey;
    }
    */
    
     //PKCS8 DER Format
    /*
    public static PrivateKey readPrivateKey(String derFile){
        try{
            byte[] keyBytes = Files.readAllBytes(Paths.get(derFile));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException ex){
            throw new SecurityException("Invalid Certificate Format or Specification: "+ex.getMessage(),ex);
        }
        catch(IOException ex){
            throw new SecurityException("Unable to read file: "+ex.getMessage(),ex);
        }
    }
    */
    
    
    
}
