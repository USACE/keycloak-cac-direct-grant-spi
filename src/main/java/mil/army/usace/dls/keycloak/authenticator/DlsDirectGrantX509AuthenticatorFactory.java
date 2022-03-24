/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mil.army.usace.dls.keycloak.authenticator;

import java.util.ArrayList;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 *
 * @author rsgoss
 */
public class DlsDirectGrantX509AuthenticatorFactory implements AuthenticatorFactory{
    
    public static final String PROVIDER_ID = "dls-x509-authentication-factory";
    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    @Override
    public Authenticator create(KeycloakSession ks) {
        System.out.println("CWBI SPI -> Create DLSAuthenticatorFactory");
        return new DlsDirectGrantX509Authenticator();
    }

    @Override
    public void init(Config.Scope scope) {
        System.out.println("CWBI SPI -> Init DlsAuthenticatorFactory");
    }

    @Override
    public void postInit(KeycloakSessionFactory ksf) {
        System.out.println("CWBI SPI -> Finished initializing DlsAuthenticatorFactory");
    }

    @Override
    public void close() {
        System.out.println("CWBI SPI -> Closing DlsAuthenticationFactory");
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "CWBI X509 Direct Grant";
    }

    @Override
    public String getReferenceCategory() {
        return PROVIDER_ID;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Civil Works Business Intelligence Direct Grant Authenticator";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    
}
