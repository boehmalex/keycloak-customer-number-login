package de.adesso;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.KeycloakSession;

public class CustomerNumberAuthenticatorFactory extends UsernamePasswordFormFactory {

    @Override
    public Authenticator create(KeycloakSession session) {
        return new CustomerNumberAuthenticator();
    }

    @Override
    public String getId() {
        return "customer-number-auth";
    }

    @Override
    public String getDisplayType() {
        return "customer number based login";
    }

    @Override
    public String getHelpText() {
        return "Enables login via costumer number on initial login form.";
    }
}
