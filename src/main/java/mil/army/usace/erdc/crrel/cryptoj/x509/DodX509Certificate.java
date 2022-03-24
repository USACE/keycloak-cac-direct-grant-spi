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
import java.util.List;
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
   
    
    public DodX509Certificate(X509Certificate cert) throws IOException, CertificateParsingException, CertificateEncodingException, CertificateException{
        this(cert,null);
    }
    
    public DodX509Certificate(X509Certificate cert,String alias) throws IOException, CertificateParsingException, CertificateEncodingException, CertificateException{
        this.ALIAS=alias;
        cert.checkValidity(); //@TODO is this checked by jetty?.  What about cert.verify()
        CertificateInfo certInfo = new CertificateInfo(cert);
        this.SUBJECT_DN=certInfo.getSubjectDN();
        this.SUBJECT_CN=certInfo.getRDN("CN",RDN.SUBJECT);
        this.EDIPI=certInfo.getEDIPI(SUBJECT_CN);        
        this.cert=cert;
        this.SERIAL_NUMBER=cert.getSerialNumber();
        //this.SUBJECT_ALTERNATIVE_NAMES=certInfo.getSubjectAlternativeNames();
        /*
        this.ISSUER_CN=certInfo.getRDN("CN", RDN.ISSUER);
        this.SUBJECT_ALTERNATIVE_NAMES=certInfo.getSubjectAlternativeNames();
        this.CRL_DISTRIBUTION_POINTS=certInfo.getCrlDistributionPoints();
        this.AUTHORITY_INFORMATION_ACCESS=certInfo.getAuthorityInformationAccess();
        this.CERT_KEY_USAGE=certInfo.getCertKeyUsage();
        this.EXTENDED_KEY_USAGE=certInfo.getExtendedKeyUsage();
        this.CERTIFICATE_POLICIES=certInfo.getCertificatePolicies();
        this.checkValidForNonRepudiation();
        this.checkValidForTlsWebClientAuthentication();
        */

        //this.validateOCSP();
    }
    
    
    
    //@TODO fix this....get from OID
    public String getEmail() throws IOException, CertificateParsingException{
        CertificateInfo certInfo = new CertificateInfo(cert);
        for(String altName : certInfo.getSubjectAlternativeNames()){
            if(altName.contains("@mail.mil")){
                return altName;
            }
        }
        return null;
    }
    
    public String getName() {
        return this.SUBJECT_CN.substring(0,this.SUBJECT_CN.lastIndexOf("."));
    }
    
    /*
    public Boolean validateOCSP()  {
        boolean isValid=false;
        try{
            CertificateInfo certInfo = new CertificateInfo(cert);
            HashMap<String,String> AUTHORITY_INFORMATION_ACCESS = certInfo.getAuthorityInformationAccess();
            URL url = new URL(AUTHORITY_INFORMATION_ACCESS.get(AuthorityInformationAccessCodes.CAISSUERS_URL.getOid()));
            URL ocspUrl = new URL(AUTHORITY_INFORMATION_ACCESS.get(AuthorityInformationAccessCodes.OCSP_URL.getOid()));
            ByteArrayOutputStream bais = new ByteArrayOutputStream();
            try(InputStream is = url.openStream ()){
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                X509Certificate cacert=(X509Certificate)certFactory.generateCertificate(is);
                isValid=OCSPValidator.isValid(this.cert, cacert, ocspUrl);
            }
        }
        catch(IOException | CertificateException | OCSPException | OperatorCreationException ex){
            logger.error(String.format("Error Validating Certificate: %s",ex.getMessage()));
        }
        return isValid;
    }
    */
    
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
            
            
    
    
    /*
    private void checkForCertInCache(Long edipi){
        //certCache.get(edipi);
    }
    
    private Boolean isValidCientAuth(){
        
        return true;
    }
    
    
    private Boolean isRevoked(){
        //check against crl
        return true;
    }
    */
    /*
    private Boolean isIssuedByDod(){
        if(CERTIFICATE_POLICIES.containsAll(new List))
        return false;
    }
    */
    
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
