/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mil.army.usace.erdc.crrel.cryptoj.x509;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
//import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
//import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author k3endrsg
 */
public class CertificateInfo {
    
    private final X509Certificate cert;
    
    private final Logger logger = LoggerFactory.getLogger(getClass());
    
    public CertificateInfo(X509Certificate cert){
        this.cert=cert;
    }
    
    public static enum DodCertificatePolicies{
        US_DOD_MEDIUM_HARDWARE("2.16.840.1.101.2.1.11.9"),
        US_DOD_MEDIUM_HARDWARE_2048("2.16.840.1.101.2.1.11.9");
        
        private String oid;
        
        DodCertificatePolicies(String oid){
            this.oid=oid;
        }
        
        public static String getValueFromOid(String oid) {
            for(DodCertificatePolicies dcp : values()) {
                if(dcp.oid.equals(oid)){
                    return dcp.toString();
                }
            }
            return null;
        }
        
        public static DodCertificatePolicies getFromOid(String oid) {
            for(DodCertificatePolicies dcp : values()) {
                if(dcp.oid.equals(oid)){
                    return dcp;
                }
            }
            return null;
        }
        
    }
    
    public static enum KeyUsage{
        DIGITALSIGNATURE(0),
        NONREPUDIATION(1),
        KEYENCIPHERMENT(2),
        DATAENCIPHERMENT(3),
        KEYAGREEMENT(4),
        KEYCERTSIGN(5),
        CRLSIGN(6),
        ENCIPHERONLY(7),
        DECIPHERONLY(8);
        
        private final int id;
        
        KeyUsage(int id){
            this.id=id;
        }
        
        public static String getValueFromId(int id) {
            for(KeyUsage ku : values()) {
                if(ku.id==id) return ku.toString();
            }
            return null;
        }
        
        public static KeyUsage getFromId(int id) {
            for(KeyUsage ku : values()) {
                if(ku.id==id) return ku;
            }
            return null;
        }
    }
    
    
    public static enum ExtendedKeyUsage{
        ANYEXTENDEDKEYUSAGE("1.3.6.1.5.5.7.3.0"),
        SERVERAUTH("1.3.6.1.5.5.7.3.1"),
        CLIENTAUTH("1.3.6.1.5.5.7.3.2"),
        CODESIGNING("1.3.6.1.5.5.7.3.3"),
        EMAILPROTECTION("1.3.6.1.5.5.7.3.4"),
        IPSECENDSYSTEM("1.3.6.1.5.5.7.3.5"),
        IPSECTUNNEL("1.3.6.1.5.5.7.3.6"),
        IPSECUSER("1.3.6.1.5.5.7.3.7"),
        TIMESTAMPING("1.3.6.1.5.5.7.3.8"),
        SMARTCARDLOGON("1.3.6.1.4.1.311.20.2.2"),
        OCSPSIGNER("1.3.6.1.5.5.7.3.9");
    
        private String oid;
        
        ExtendedKeyUsage(String oid){
            this.oid=oid;
        }
        
        public static String getValueFromOid(String oid) {
            for(ExtendedKeyUsage eku : values()) {
                if(eku.oid.equals(oid)){
                    return eku.toString();
                }
            }
            return null;
        }
        
        public static ExtendedKeyUsage getFromOid(String oid) {
            for(ExtendedKeyUsage eku : values()) {
                if(eku.oid.equals(oid)){
                    return eku;
                }
            }
            return null;
        }
    }
     
    
    public static enum X509Ext{
        
        SubjectKeyIdentifier("2.5.29.14"),
        KeyUsage("2.5.29.15"),
        PrivateKeyUsage("2.5.29.16"),
        SubjectAlternativeName("2.5.29.17"),
        IssuerAlternativeName("2.5.29.18"),
        BasicConstraints("2.5.29.19"),
        NameConstraints("2.5.29.28"),
        IssuingDistributionPoint("2.5.29.30"),
        CrlDistributionPoints("2.5.29.31"),
        PolicyMappings("2.5.29.33"),
        AuthorityKeyIdentifier("2.5.29.35"),
        PolicyConstraints("2.5.29.36"),
        AuthorityInformationAccess("1.3.6.1.5.5.7.1.1");
  
        private String oid;
        
        X509Ext(String oid){
            this.oid=oid;
        }
        
        public String getOid(){
            return this.oid;
        }
        
    }
    
    public static enum RDN{
        SUBJECT,
        ISSUER
    }
    
    public static enum AuthorityInformationAccessCodes{
        OCSP_URL("1.3.6.1.5.5.7.48.1"),
        CAISSUERS_URL("1.3.6.1.5.5.7.48.2");
        
        private final String oid;
        
        AuthorityInformationAccessCodes(String oid){
            this.oid=oid;
        }
        
        public String getOid(){
            return this.oid;
        }
    }
    
    public String getSubjectDN(){
        return cert.getSubjectDN().getName();
    }
    
    //Relative Distinguished Name (RDN)
    //@TODO...assumtion is that CN will always be first item in RDN...not sure if this is completely correct.
    public String getRDN(String rdnName,RDN rdnType) throws CertificateException{
        X500Principal principal;
        if(rdnType==RDN.SUBJECT)
            principal=cert.getSubjectX500Principal();
        else
            principal=cert.getIssuerX500Principal();
        String principalName=principal.getName();
        String[] rdnArray=principalName.split(",");
        for(String rdn:rdnArray){
            String[] rdnParts=rdn.split("=");
            if(rdnParts[0].equals(rdnName)){
                return rdnParts[1];
            }
        }
        throw new CertificateException("Unable to find RDN: "+rdnName);     
    }
    
    
    
    //extracts the electronic data interchange personal identifier from the rdn
    //last item in field separated by '.'
    public Long getEDIPI(String cnName){
        String[] cnComponents = cnName.split("\\.");
        return Long.parseLong(cnComponents[cnComponents.length-1]);
    }
    
    public String getEmail() throws CertificateParsingException{
        Collection<List<?>> sams =cert.getSubjectAlternativeNames();
        String email=null;
        if(sams!=null && sams.size()>0){
            ArrayList<List<?>> samList = new ArrayList<>(sams);
            email=(String)samList.get(0).get(1);   
        }
        return email;
    }
    
    public List<KeyUsage> getCertKeyUsage(){
        List<KeyUsage> certUsage = new ArrayList<>();
        boolean[] keyusage = cert.getKeyUsage();
        if(keyusage!=null){
            for(int i=0;i<keyusage.length;i++){
                if(keyusage[i])
                    certUsage.add(KeyUsage.getFromId(i));
            }
        }
        return certUsage;
    }
    
    public List<String> getCertKeyUsageStrings(){
        List<String> certUsage = new ArrayList<>();
        boolean[] keyusage = cert.getKeyUsage();
        if(keyusage!=null){
            for(int i=0;i<keyusage.length;i++){
                if(keyusage[i])
                    certUsage.add(KeyUsage.getValueFromId(i));
            }
        }
        return certUsage;
    }
    
    
    public List<ExtendedKeyUsage> getExtendedKeyUsage() throws CertificateParsingException{
        List<ExtendedKeyUsage> extCertUsage = new ArrayList<>();
        List<String> extKeyUsage = cert.getExtendedKeyUsage();
        if(extKeyUsage!=null){
            for(String extKeyUse:extKeyUsage){
                    extCertUsage.add(ExtendedKeyUsage.getFromOid(extKeyUse));
            }
        }
        return extCertUsage;
    }
    
    public List<String> getExtendedKeyUsageStrings() throws CertificateParsingException{
        List<String> extCertUsage = new ArrayList<>();
        List<String> extKeyUsage = cert.getExtendedKeyUsage();
        if(extKeyUsage!=null){
            for(String extKeyUse:extKeyUsage){
                    extCertUsage.add(ExtendedKeyUsage.getValueFromOid(extKeyUse));
            }
        }
        return extCertUsage;
    }
    
    public List<String> getCertificatePolicies() throws CertificateEncodingException, IOException{
        X509CertificateHolder ch = new X509CertificateHolder(cert.getEncoded());
        Extension certPol = ch.getExtension(Extension.certificatePolicies);
        CertificatePolicies cp = CertificatePolicies.fromExtensions(ch.getExtensions());
        List<String> polList = new ArrayList<>();
        for(PolicyInformation pi:cp.getPolicyInformation()){
            polList.add(pi.getPolicyIdentifier().toString());
        }
        return polList;
    }
    
    /*
    public List<String> getCrlDistributionPoints() throws CertificateParsingException, IOException {
        byte[] crldpExt = cert.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
        if (crldpExt == null) {
            return new ArrayList<String>();
        }
        ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crldpExt));
        ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
        DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
        byte[] crldpExtOctets = dosCrlDP.getOctets();
        ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
        ASN1Primitive derObj2 = oAsnInStream2.readObject();
        CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
        List<String> crlUrls = new ArrayList<String>();
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                // Look for an URI
                for (int j = 0; j < genNames.length; j++) {
                    if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = DERIA5String.getInstance(genNames[j].getName()).getString();
                        crlUrls.add(url);
                    }
                }
            }
        }
        return crlUrls;
    }
    */
    
    public List<String> getSubjectAlternativeNames() throws IOException, CertificateParsingException {
        List<String> identities = new ArrayList<String>();
        
        Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
        if (altNames == null)
            return Collections.emptyList();
        for (List item : altNames) {
            Integer type = (Integer) item.get(0);
            if (type == 0){
                ASN1InputStream decoder = new ASN1InputStream((byte[]) item.toArray()[1]);
                ASN1Encodable encoded = decoder.readObject();
                encoded = ((DLSequence) encoded).getObjectAt(1);
                encoded = ((ASN1TaggedObject) encoded).getObject();
                encoded = ((ASN1TaggedObject) encoded).getObject();
                String identity="";
                if(encoded instanceof DERUTF8String){
                    identity = ((DERUTF8String) encoded).getString();                
                } else if (encoded instanceof DEROctetString) {
                    //DEROctetString octString = ((DEROctetString)encoded);
                    //InputStream inStream = octString.getOctetStream();
                    //ASN1InputStream asnInputStream = new ASN1InputStream(decoder);
                    //ASN1Primitive derObject = decoder.readObject();
                    //if (derObject instanceof ASN1String){
                    //    ASN1String s = (ASN1String)derObject;
                    //    identity = s.getString();
                    //}
                    logger.warn("DEROctet Decoding is currently unsupported for Subject Alternative Name");
                } else {
                   throw new CertificateParsingException("Invalid Subject Alternative Name");  
                }
                identities.add(identity);
            }
            else if (type==1){
                identities.add((String)item.get(1));
            }
        }
        return identities;
    }
    
    /*
    public HashMap<String,String> getAuthorityInformationAccess() throws IOException{
        HashMap<String,String> aiaMap = new HashMap<>();
        byte[] bytes = cert.getExtensionValue(X509Ext.AuthorityInformationAccess.getOid());
        ASN1Primitive ap = X509ExtensionUtil.fromExtensionValue(bytes);
        ASN1Sequence seq = ASN1Sequence.getInstance(ap);
        AuthorityInformationAccess access = AuthorityInformationAccess.getInstance(seq);
        AccessDescription[] ads = access.getAccessDescriptions();
        for(AccessDescription ad:ads){
            GeneralName gn = ad.getAccessLocation();
            aiaMap.put(ad.getAccessMethod().getId(),gn.getName().toString());
         }
        return aiaMap;
    }
    */
    
}
