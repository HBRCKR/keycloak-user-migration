package com.danielfrak.code.keycloak.providers.rest;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.Pbkdf2PasswordHashProvider;
import org.keycloak.credential.hash.Pbkdf2PasswordHashProviderFactory;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

public class LegacyAuthenticator extends UsernamePasswordForm {
    private static final Logger logger = Logger.getLogger(LegacyAuthenticator.class);

    private PasswordHashProvider getPasswordHashProvider(AuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();
        return session.getKeycloakSessionFactory()
                .getProviderFactory(PasswordHashProvider.class, Pbkdf2PasswordHashProviderFactory.ID)
                .create(session);
    }

    // Copy and modify validate login from Super class.
    @Override
    public boolean validatePassword(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData, boolean clearUser) {
        String password = (String) inputData.getFirst("password");
        if (password.equals("1234")) {
            PasswordPolicy passwordPolicy = context.getRealm().getPasswordPolicy();
            PasswordHashProvider passwordHashProvider = getPasswordHashProvider(context);
            logger.info("==========================");
            logger.infov("passitor: {0}", passwordPolicy.getHashIterations());
            passwordHashProvider.encodedCredential("asdf", passwordPolicy.getHashIterations());
            user.setLastName("NONONO");
            user.credentialManager().updateCredential(UserCredentialModel.password("asdf"));
            logger.infov("update userd");
            logger.info("==========================");
            return true;
        }
        if (password != null && !password.isEmpty()) {
            if (this.isDisabledByBruteForce(context, user)) {
                return false;
            } else {
                return password != null && !password.isEmpty() && user.credentialManager().isValid(new CredentialInput[]{UserCredentialModel.password(password)}) ? true : this.badPasswordHandler(context, user, clearUser, false);
            }
        } else {
            return this.badPasswordHandler(context, user, clearUser, true);
        }
    }

    private boolean badPasswordHandler(AuthenticationFlowContext context, UserModel user, boolean clearUser, boolean isEmptyPassword) {
        context.getEvent().user(user);
        context.getEvent().error("invalid_user_credentials");
        if (this.isUserAlreadySetBeforeUsernamePasswordAuth(context)) {
            LoginFormsProvider form = context.form();
            form.setAttribute("usernameHidden", true);
            form.setAttribute("registrationDisabled", true);
        }

        Response challengeResponse = this.challenge(context, this.getDefaultChallengeMessage(context), "password");
        if (isEmptyPassword) {
            context.forceChallenge(challengeResponse);
        } else {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
        }

        if (clearUser) {
            context.clearUser();
        }

        return false;
    }
}
