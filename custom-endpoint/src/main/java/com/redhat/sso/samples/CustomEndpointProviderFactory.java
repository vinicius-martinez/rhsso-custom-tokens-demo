package com.redhat.sso.samples;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class CustomEndpointProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "custom-endpoint";

    @Override
    public void close() {
        // TODO Auto-generated method stub
        
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new CustomEndpointProvider(session);    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Scope arg0) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void postInit(KeycloakSessionFactory arg0) {
        // TODO Auto-generated method stub
        
    }

    
}