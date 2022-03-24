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

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author k3endrsg
 */
public class OCSPValidator {
    
    private static final Logger logger = LoggerFactory.getLogger(OCSPValidator.class);
    
    public static boolean isValid(X509Certificate cert, X509Certificate cacert, URL ocspUrl) throws OCSPException, OperatorCreationException, IOException, CertificateEncodingException{
        OCSPReqBuilder builder = new OCSPReqBuilder();
        java.security.Security.addProvider(new BouncyCastleProvider());
        CertificateID certId = new CertificateID(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1), 
                                                 new X509CertificateHolder(cacert.getEncoded()), 
                                                 cert.getSerialNumber());
        builder.addRequest(certId);
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(nonce.toByteArray()));
        builder.setRequestExtensions(new Extensions(new Extension[] { ext }));
        OCSPReq ocspReq=builder.build();
        ////////////
        HttpURLConnection con=(HttpURLConnection)ocspUrl.openConnection();
        con.setRequestProperty("Content-Type","application/ocsp-request");
        con.setRequestProperty("Accept","application/ocsp-response");
        con.setDoOutput(true);
        OutputStream out=con.getOutputStream();
        DataOutputStream dataOut=new DataOutputStream(new BufferedOutputStream(out));
        dataOut.write(ocspReq.getEncoded());
        dataOut.flush();
        dataOut.close();
        ////////////////
        InputStream in=con.getInputStream();
        if (in == null)   throw new IOException("Nothing Returned");
        BasicOCSPResp basicResp=(BasicOCSPResp)new OCSPResp(in).getResponseObject();
        System.out.println("Request Received");
        con.disconnect();
        out.close();
        in.close();
        System.out.println(basicResp.toString());
        SingleResp[] singleResponses=basicResp.getResponses();
        if(singleResponses.length!=1){
            logger.debug(String.format("Invalid number of OCSP responses.  Expected 1 received %d", singleResponses.length));
            return false; //should only be checking single cert
        }
        else{
            CertificateStatus status = singleResponses[0].getCertStatus();
            if(status==null){
                logger.debug(String.format("Validated %s on OCSP at %s", cert.getIssuerX500Principal().getName(),ocspUrl.toString()));
                return true; //insane isn't it.
            }
            else{
                logger.debug(String.format("Certificate Invalid: %s", status.getClass().getName()));
                return false;
            }
        }            
    }
    
}
