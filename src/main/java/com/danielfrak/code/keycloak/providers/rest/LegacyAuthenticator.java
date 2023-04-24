package com.danielfrak.code.keycloak.providers.rest;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.credential.CredentialInput;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

public class LegacyAuthenticator extends UsernamePasswordForm {
    private static final Logger logger = Logger.getLogger(LegacyAuthenticator.class);

    // Copy and modify validate login from Super class.
    @Override
    public boolean validatePassword(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData, boolean clearUser) {
        String password = (String) inputData.getFirst("password");
        // Check user have "legacy_password" attribute, if user hava it then validate password using md5 hash.
//        if (user.getFirstAttribute("legacy_password") != null) {
//            String legacyPassword = user.getFirstAttribute("legacy_password");
//            String passwordHash = this.getPasswordHashProvider(context).encode(password, 10000);
//            // If password is valid then update user password to new hash.
//            if (legacyPassword.equals(passwordHash)) {
//                logger.info("Legacy password is valid, updating user password.");
//                user.setSingleAttribute("legacy_password", null);
//                user.credentialManager().updateCredential(UserCredentialModel.password(password));
//                return true;
//            }
//        }
        logger.infov("lp: {0}", user.getFirstAttribute("legacy_credentials"));

        if (password.equals("1234")) {
            logger.info("Legacy password is valid, updating user password.");
            RealmModel realmModel = context.getRealm();
            UserProvider userProvider = context.getSession().getProvider(UserProvider.class);
            UserModel newModel = userProvider.getUserById(realmModel, user.getId());
            logger.infov("new user: {0}", newModel);
            logger.infov("attributes: {0}", newModel.getAttributes());
            newModel.setSingleAttribute("legacy_credentials", null);
            newModel.removeAttribute("legacy_credentials");
            logger.infov("after - attributes: {0}", newModel.getAttributes());

            user.credentialManager().updateCredential(UserCredentialModel.password("asdf"));
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
