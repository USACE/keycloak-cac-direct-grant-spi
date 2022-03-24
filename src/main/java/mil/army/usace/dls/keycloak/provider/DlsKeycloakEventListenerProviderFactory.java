/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mil.army.usace.dls.keycloak.provider;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;



/**
 *
 * @author rsgoss
 */
public class DlsKeycloakEventListenerProviderFactory implements EventListenerProviderFactory{

    @Override
    public EventListenerProvider create(KeycloakSession ks) {
        return new DlsKeycloakEventListenerProvider();
    }

    @Override
    public void init(Config.Scope scope) {
        System.out.println("CWBI SPI => Initializing Factory");
    }

    @Override
    public void postInit(KeycloakSessionFactory ksf) {
        System.out.println("CWBI SPI => Finished Initializing Factory");
    }

    @Override
    public void close() {
        System.out.println("CWBI SPI => Closing");
    }

    @Override
    public String getId() {
        return "dls_keycloak_event_listener";
    }
    
}
