/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mil.army.usace.dls.keycloak.authenticator;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import mil.army.usace.erdc.crrel.cryptoj.UsaceCrypto;
import mil.army.usace.erdc.crrel.cryptoj.x509.DodX509Certificate;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import java.util.logging.*;

/**
 *
 * @author rsgoss
 */

public class DlsDirectGrantX509Authenticator implements Authenticator {
    private final String firstName = "";
    private final String lastName = "";
    private final Logger log = Logger.getLogger("DlsDirectGrantX509Authenticator");

    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        try {
            HttpRequest req = authenticationFlowContext.getHttpRequest();
            List<String> certStrList = req.getHttpHeaders().getRequestHeader("SSL_CLIENT_CERT");
            if (certStrList.size() == 1) {
                String pemCert = certStrList.get(0);
                X509Certificate cert = UsaceCrypto.getCertFromPEM(pemCert);
                DodX509Certificate dodCert = new DodX509Certificate(cert);
                KeycloakSession session = authenticationFlowContext.getSession();
                RealmModel realm = authenticationFlowContext.getRealm();
                String username = extractCNFromNormalizedDN(dodCert.SUBJECT_DN);
                UserModel existingUser = session.users().getUserByUsername(realm, username);
                if (existingUser == null) {
                    log.info(String.format("DLS SPI LOG -> creating user %s.", username));
                    UserModel federatedUser = session.users().addUser(realm, username);
                    federatedUser.setEnabled(true);
                    federatedUser.setEmail(dodCert.getEmail());
                    federatedUser.setFirstName(firstName);
                    federatedUser.setLastName(lastName);
                    federatedUser.setSingleAttribute("subjectDN", dodCert.SUBJECT_DN);
                    federatedUser.setSingleAttribute("cacUID", dodCert.EDIPI.toString());
                    federatedUser.setSingleAttribute("pivID", dodCert.getPivId());
                    authenticationFlowContext.setUser(federatedUser);
                } else {
                    log.info(String.format("DLS SPI LOG -> Existing user detected with %s '%s' .", UserModel.USERNAME,
                            existingUser.getUsername()));
                    authenticationFlowContext.setUser(existingUser);
                }
            } else {
                authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS);
            }
            authenticationFlowContext.success();
        } catch (IOException | CertificateException ex) {
            throw new AuthenticationFlowException(ex, AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    @Override
    public void action(AuthenticationFlowContext afc) {
        log.info("DLS SPI LOG -> Got DLSAuthenticator Action");
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession ks, RealmModel rm, UserModel um) {
        // All users for this realm are expected to use...
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession ks, RealmModel rm, UserModel um) {
        // If configuredFor() always returns true, this shouldn't be called, so do
        // nothing
    }

    @Override
    public void close() {
        System.out.println("DLS SPI LOG -> Got DLSAuthenticator Close");
    }

    private String extractCNFromNormalizedDN(String normDN) {
        Pattern pattern = Pattern.compile(".*CN=?(.+[0-9])(?:,|$)");
        Matcher matcher = pattern.matcher(normDN);
        while (matcher.find()) {
            String CN = matcher.group(1);
            return CN;
        }
        return "";
    }

}
