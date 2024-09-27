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
package mil.army.usace.erdc.crrel.cryptoj.x509;

import mil.army.usace.erdc.crrel.cryptoj.x509.CertificateInfo;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import mil.army.usace.erdc.crrel.cryptoj.x509.CertificateInfo.ExtendedKeyUsage;
import mil.army.usace.erdc.crrel.cryptoj.x509.CertificateInfo.KeyUsage;
import mil.army.usace.erdc.crrel.cryptoj.x509.CertificateInfo.RDN;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author k3endrsg
 */
public class DodX509Certificate {
    
    private static final Logger logger = LoggerFactory.getLogger(DodX509Certificate.class);
    
    public final X509Certificate cert;
    public final BigInteger SERIAL_NUMBER;
    public final String SUBJECT_CN;
    public final String SUBJECT_DN;
    public final Long EDIPI;
    public final String ALIAS;
    public final int RFC_EMAIL=1;
    public final boolean CHECK_POLICY = true;
    
    //https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/txt/unclass-pki_interop_assurance_levels.txt
    //dod approved assurance levels
    Map<String, String> dodPolicyMap = new HashMap<String, String>() {{
        put("2.16.840.1.101.2.1.11.5","id-US-dod-medium");			
        put("2.16.840.1.101.2.1.11.9","id-US-dod-mediumhardware");				
        put("2.16.840.1.101.2.1.11.10","id-US-dod-PIV-Auth");		
        put("2.16.840.1.101.2.1.11.17","id-US-dod-mediumNPE");				
        put("2.16.840.1.101.2.1.11.18","id-US-dod-medium-2048");				
        put("2.16.840.1.101.2.1.11.19","id-US-dod-mediumHardware-2048");				
        put("2.16.840.1.101.2.1.11.20","id-US-dod-PIV-Auth-2048");				
        put("2.16.840.1.101.2.1.11.31","id-US-dod-peerInterop");				
        put("2.16.840.1.101.2.1.11.36","id-US-dod-mediumNPE-112");				
        put("2.16.840.1.101.2.1.11.37","id-US-dod-mediumNPE-128");	
        put("2.16.840.1.101.2.1.11.38","id-US-dod-mediumNPE-192");	
        put("2.16.840.1.101.2.1.11.39","id-US-dod-medium-112");				
        put("2.16.840.1.101.2.1.11.40","id-US-dod-medium-128");	
        put("2.16.840.1.101.2.1.11.41","id-US-dod-medium-192");	
        put("2.16.840.1.101.2.1.11.42","id-US-dod-mediumHardware-112");				
        put("2.16.840.1.101.2.1.11.43","id-US-dod-mediumHardware-128");
        put("2.16.840.1.101.2.1.11.44","id-US-dod-mediumHardware-192");
        put("2.16.840.1.101.2.1.11.59","id-US-dod-admin");
        put("2.16.840.1.101.2.1.11.60","id-US-dod-internalNPE-112");
        put("2.16.840.1.101.2.1.11.61","id-US-dod-internalNPE-128");
        put("2.16.840.1.101.2.1.11.62","id-US-dod-internalNPE-192");
    }};
   
    
    public DodX509Certificate(X509Certificate cert) throws IOException, CertificateParsingException, CertificateEncodingException, CertificateException{
        this(cert,null);
    }
    
    public DodX509Certificate(X509Certificate cert,String alias) throws IOException, CertificateParsingException, CertificateEncodingException, CertificateException{
        this.ALIAS=alias;
        cert.checkValidity(); //@TODO is this checked by jetty?.  What about cert.verify()
        CertificateInfo certInfo = new CertificateInfo(cert);
        if(CHECK_POLICY){
            checkDodAssurancePolicies(certInfo);            
        }
        
        this.SUBJECT_DN=certInfo.getSubjectDN();
        this.SUBJECT_CN=certInfo.getRDN("CN",RDN.SUBJECT);
        this.EDIPI=certInfo.getEDIPI(SUBJECT_CN);        
        this.cert=cert;
        this.SERIAL_NUMBER=cert.getSerialNumber();
    }
    
    
    
   public String getEmail() throws IOException, CertificateParsingException{
        CertificateInfo certInfo = new CertificateInfo(cert);
        Map<Integer,String> altNames = certInfo.getSubjectAlternativeNameMap();
            if (altNames.containsKey(RFC_EMAIL)){
                return altNames.get(RFC_EMAIL);
            } 
        return null;
    }
    
    
    public String getName() {
        return this.SUBJECT_CN.substring(0,this.SUBJECT_CN.lastIndexOf("."));
    }
    
    public String getPivId() throws IOException, CertificateParsingException{
        CertificateInfo certInfo = new CertificateInfo(cert);
        List<String> sams=certInfo.getSubjectAlternativeNames();
        for(String sam:sams){
            if(sam.endsWith("@mil")){
                return sam;
            }
        }
        throw new CertificateParsingException("Unable to find PIV Number");
    }
    
    private void checkValidForNonRepudiation(CertificateInfo certInfo) throws CertificateException{
        //@TODO...probably should work with list of enum not strings....
        if(!certInfo.getCertKeyUsage().contains(KeyUsage.NONREPUDIATION)){
            throw new CertificateException("KEY IS NOT VALID FOR CLIENT AUTHENTICATION PER KEY USAGE (2.5.29.15)");
        }
    }
    
    private void checkValidForTlsWebClientAuthentication(CertificateInfo certInfo) throws CertificateException{
        if(!certInfo.getExtendedKeyUsage().contains(ExtendedKeyUsage.CLIENTAUTH)){
           throw new CertificateException("KEY IS NOT VALID FOR CLIENT AUTHENTICATION PER EXTENDED KEY USAGE (1.3.6.1.5.5.7.3.2)"); 
        }
    }
    
    private void checkDodAssurancePolicies(CertificateInfo certInfo) throws CertificateException {
        try{
            List<String> policies = certInfo.getCertificatePolicies();
            for(String key:dodPolicyMap.keySet()){
                if (policies.contains(key)){
                    return;
                }
            }
            throw new CertificateException("CERTIFICATE DOES NOT INCLUDE DOD ASSURANCE POLICY");
        } catch(IOException ex){
            throw new CertificateException("ERROR READING CERTIFICATE POLICIES"); 
        }
    }
    
    
    @Override
    public String toString(){
        CertificateInfo certInfo = new CertificateInfo(cert);
        String ISSUER_CN="";
        try {
            ISSUER_CN=certInfo.getRDN("CN", RDN.ISSUER);
        } catch (CertificateException ex) {
            java.util.logging.Logger.getLogger(DodX509Certificate.class.getName()).log(Level.SEVERE, null, ex);
        }
        return String.format("SUBJECT CN: %s\n"+
                             "ISSUER CN: %s\n"+
                             "CERT: %s",
                this.SUBJECT_CN,
                ISSUER_CN,
                this.ALIAS
                
        );
    }
    
}
