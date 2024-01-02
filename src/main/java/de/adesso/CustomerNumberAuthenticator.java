package de.adesso;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

import java.util.List;

import static org.keycloak.events.Details.USERNAME;
import static org.keycloak.events.Errors.USER_NOT_FOUND;
import static org.keycloak.services.managers.AuthenticationManager.FORM_USERNAME;

public class CustomerNumberAuthenticator extends UsernamePasswordForm {

    private static final Logger logger = Logger.getLogger(CustomerNumberAuthenticator.class);

    @Override
    public boolean validateUserAndPassword(AuthenticationFlowContext context, MultivaluedMap inputData) {
        String username = (String) inputData.getFirst(FORM_USERNAME);

        if (username == null) {
            context.getEvent().error(USER_NOT_FOUND);
            setInvalidUserError(context);
            return false;
        }

        username = username.trim();
        context.getEvent().detail(USERNAME, username);
        context.getAuthenticationSession().setAuthNote(ATTEMPTED_USERNAME, username);

        List<UserModel> users = context.getSession().users()
                .searchForUserByUserAttributeStream(context.getRealm(), "customer_number", username)
                .toList();

        UserModel user;
        if (users.isEmpty()) {
            logger.infof("No keycloak user found for potential customer number '%s'. " +
                    "Trying to load by username/email.", username);
            user = context.getSession().users().getUserByUsername(context.getRealm(), username);

            if (user == null && context.getRealm().isLoginWithEmailAllowed()) {
                user = context.getSession().users().getUserByEmail(context.getRealm(), username);
            }
        } else if (users.size() == 1) {
            user = users.get(0);
            logger.infof("Found keycloak user for customer number %s", username);
        } else {
            logger.warnf("Found more than one user with given customer number %s", username);
            setInvalidUserError(context);
            return false;
        }

        if (user == null || !validatePassword(context, user, inputData, false)) {
            logger.errorf("Invalid username or password");
            setInvalidUserError(context);
            return false;
        }

        logger.infof("User %s successfully logged in", user.getUsername());
        context.setUser(user);
        return true;
    }

    private void setInvalidUserError(AuthenticationFlowContext context) {
        Response challengeResponse = challenge(context, Messages.INVALID_USER);
        context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
    }
}
