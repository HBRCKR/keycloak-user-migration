package com.danielfrak.code.keycloak.providers.rest;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public class LegacyAuthenticatorFactory implements AuthenticatorFactory {
    public static final String ID = "legacyauthenticator";
    private static final String URL = "url";

    private static final Authenticator AUTHENTICATOR_INSTANCE = new LegacyAuthenticator();

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return AUTHENTICATOR_INSTANCE;
    }

    @Override
    public String getDisplayType() {
        return "Legacy Authenticator";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.ALTERNATIVE};
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Try to challenge Legacy login";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty name = new ProviderConfigProperty(URL, "test label", "text test", ProviderConfigProperty.STRING_TYPE, "");
        return Collections.singletonList(name);
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return ID;
    }
}
