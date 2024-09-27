/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mil.army.usace.erdc.crrel.cryptoj.x509;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author k3endrsg
 */
public class Crl {
    
    public static String CRA_ZIP;
    
    public final HashMap<BigInteger,String> revokedCertsHash=new HashMap<>();
    
    private static final Logger logger = LoggerFactory.getLogger(Crl.class);
    
    public Crl(){
        try{
            File craDir= new File(CRA_ZIP);
            List<File> crlFiles= getCrlFiles(craDir);
            for(File crlFile : crlFiles){
                loadCrl(crlFile);
            }
            logger.info(String.format("Successfully loaded %d CRL files.",crlFiles.size()));
            logger.info(String.format("%d Revoked Certs",revokedCertsHash.size()));
        }
        catch(CRLException | CertificateException| IOException ex){
            logger.error("Unable to load the CRL");
        }
    }
    
    public List<File> getCrlFiles(File dir){
        File[] dirFiles=dir.listFiles();
        String pattern="([^\\s]+(\\.(?i)(crl))$)";
        List<File> crlFiles = new ArrayList<>();
        for(File file:dirFiles){
            if(file.getName().matches(pattern)){
                crlFiles.add(file);
            }
        }
        return crlFiles;        
    }
    
    public void loadCrl(File crlFile) throws FileNotFoundException, CRLException, CertificateException, IOException{
        InputStream inStream = null;
        try {
            logger.info("loading: "+crlFile.getName());
            inStream = new FileInputStream(crlFile);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL)cf.generateCRL(inStream);
            Set<? extends X509CRLEntry> revokedCerts=crl.getRevokedCertificates();
            if(revokedCerts!=null){
                for(X509CRLEntry x509:revokedCerts){
                    revokedCertsHash.put(x509.getSerialNumber(), crlFile.getName());
                    //System.out.println(x509.toString()+":"+x509.getSerialNumber());
                }
            }
        } 
        finally {
            if(inStream != null){
                inStream.close();
            }
        }
    }
    
}
