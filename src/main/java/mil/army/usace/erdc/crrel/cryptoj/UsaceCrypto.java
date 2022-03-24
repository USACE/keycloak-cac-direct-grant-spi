/*
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 
 */
package mil.army.usace.erdc.crrel.cryptoj;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import static mil.army.usace.erdc.crrel.cryptoj.CryptoUtils.decrypt;
import static mil.army.usace.erdc.crrel.cryptoj.CryptoUtils.decryptWithIv;
import static mil.army.usace.erdc.crrel.cryptoj.CryptoUtils.encrypt;
import static mil.army.usace.erdc.crrel.cryptoj.CryptoUtils.encryptWithIv;


import mil.army.usace.erdc.crrel.cryptoj.x509.DodX509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;



/**
 *
 * @author k3endrsg
 */
public class UsaceCrypto {
    
    static {
        java.security.Security.addProvider(new BouncyCastleProvider()); //used for SHA256withRSA signing
    }
    
    private final Key appKey;
    private final KeyPair systemKeyPair;
    private final int iterations=4096;
    private final int ivLength=16;
    private final int signatureLength=256;
    
    public static X509Certificate getCertFromPEM(String pem) throws IOException{
        ///////////////
        String pemFixed = "-----BEGIN CERTIFICATE-----\n"+pem.substring(28,pem.length()-25)+"\n-----END CERTIFICATE-----";
        Reader reader = new StringReader(pemFixed);
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
    
    
    public UsaceCrypto(String appKeyFilePath, String appKeyPassword, String appKeyAlias, String appKeyType,
                     String systemKeyFilePath, String systemKeyFilePassword, String systemKeyAlias, String systemKeyType) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException{
        appKey=getKey(appKeyFilePath,appKeyPassword,appKeyAlias,appKeyType);
        systemKeyPair=getKeyPair(systemKeyFilePath,systemKeyFilePassword,systemKeyAlias,systemKeyType);
    }
   
    //@TODO switch these to PksUtils class
    private Key getKey(String keyFilePath, String password, String keyAlias, String keyStoreType) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException{
       KeyStore ks = KeyStore.getInstance(keyStoreType);
        char[] pwd= password.toCharArray();
        try(java.io.FileInputStream fis = new java.io.FileInputStream(keyFilePath)){
            ks.load(fis, pwd);
            return ks.getKey(keyAlias, pwd);
        } 
    }
    
    //@TODO switch these to PksUtils class
    private KeyPair getKeyPair(String keyFilePath, String password, String keyAlias, String keyStoreType) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException{
        KeyPair kp=null;
        try(java.io.FileInputStream fis = new java.io.FileInputStream(keyFilePath)){
            KeyStore ks = KeyStore.getInstance(keyStoreType);
            char[] pwd= password.toCharArray();
            ks.load(fis, pwd);
            Key key = ks.getKey(keyAlias, pwd);
            if(key instanceof PrivateKey){
                Certificate cert = ks.getCertificate(keyAlias);
                PublicKey publicKey = cert.getPublicKey();
                kp = new KeyPair(publicKey, (PrivateKey) key);
            }
        }
        return kp;
    }
    
    public String encryptSession(HashMap sessionMap, DodX509Certificate dodcert){
        try{
            byte[] data = assemblePayload(sessionMap,dodcert);
            return encrypt(encryptWithIv(data,this.appKey),this.appKey);
        }
        catch(Exception ex){
            throw new RuntimeException(ex.getMessage());
        }
    }
    
    public HashMap decryptSession(String session, DodX509Certificate dodcert){
        try{
            byte[] dataWithIv = decrypt(session,this.appKey);
            byte[] data = decryptWithIv(dataWithIv,this.appKey);
            return (HashMap)decomposePayload(data, dodcert);
        }
        catch(Exception ex){
            throw new RuntimeException(ex.getMessage());
        }
    }
    
    ////////////////////////////////
    public byte[] assemblePayload(HashMap map, DodX509Certificate dodcert) throws IOException, NoSuchAlgorithmException, CertificateEncodingException, InvalidKeyException, SignatureException, NoSuchProviderException{
        //serialize data to byte array
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream o = new ObjectOutputStream(b);
        o.writeObject(map);
        byte[] data=b.toByteArray();
        
        //get certificate hash
        MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update(dodcert.cert.getEncoded()); 
      	byte[] certHash = md.digest();
        
        //get signature
        byte[] signature = this.sign(certHash);
        
        //
        System.out.println(String.format("data:%d, certHash:%d, signature:%d",data.length,certHash.length,signature.length));
        
        //assemble into payload
        byte[] payload=new byte[data.length+certHash.length+signature.length];  //certhash = 20 bytes and signature=128 bytes
        System.arraycopy(certHash, 0, payload, 0, certHash.length);
        System.arraycopy(signature, 0, payload, certHash.length, signature.length);
        System.arraycopy(data, 0, payload, certHash.length+signature.length, data.length);
        return payload;        
    }
    
    public HashMap decomposePayload(byte[] data, DodX509Certificate dodcert) throws IOException, NoSuchAlgorithmException, CertificateEncodingException, InvalidKeyException, SignatureException, NoSuchProviderException, ClassNotFoundException{
        //serialize data to byte array
        byte[] certHash=Arrays.copyOfRange(data, 0, 20);
        byte[] signature=Arrays.copyOfRange(data, 20, 20+signatureLength);
        if(this.validSignature(certHash, signature)){
            ByteArrayInputStream b = new ByteArrayInputStream(Arrays.copyOfRange(data,20+signatureLength,data.length));
            ObjectInputStream o = new ObjectInputStream(b);
            return (HashMap)o.readObject(); 
        }
        else{
            throw new SecurityException("Invalid Signature in Payload");
        }
    }
    
    /* Signing And Signature Validation****************************************/
    
    public byte[] sign(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        byte[] signature = null;
        //Signature dsa = Signature.getInstance("SHA1withRSA");
        Signature dsa = Signature.getInstance("SHA256withRSA","BC");
        dsa.initSign(systemKeyPair.getPrivate());
        dsa.update(data, 0, data.length);
        return dsa.sign();
    }
    
    public boolean validSignature(byte[] data, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException{
        //Signature dsa = Signature.getInstance("SHA1withRSA");
        Signature dsa = Signature.getInstance("SHA256withRSA","BC");
        dsa.initVerify(systemKeyPair.getPublic());
        dsa.update(data);
        return dsa.verify(signature);
    }
    
    

    
}
