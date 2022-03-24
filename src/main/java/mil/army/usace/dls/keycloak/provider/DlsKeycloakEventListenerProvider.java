/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mil.army.usace.dls.keycloak.provider;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;

/**
 *
 * @author rsgoss
 */
public class DlsKeycloakEventListenerProvider implements EventListenerProvider{

    @Override
    public void onEvent(Event event) {
        System.out.println("CWBI SPI => Event Occurred:" + toString(event));
    }

    @Override
    public void onEvent(AdminEvent event, boolean bln) {
         System.out.println("CWBI SPI => Admin Event Occurred:" + toString(event));
    }

    @Override
    public void close() {
        System.out.println("CWBI SPI => Closing.........");
    }
    
    private String toString(Event event){
        return event.toString();
    }
    
    private String toString(AdminEvent event){
        return event.toString();
    }
    
}
