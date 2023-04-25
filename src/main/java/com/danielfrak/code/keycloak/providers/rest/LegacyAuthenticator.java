package com.danielfrak.code.keycloak.providers.rest;

import org.apache.commons.codec.digest.DigestUtils;
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
        String legacyCredentials = user.getFirstAttribute("legacy_credentials");
        boolean isLegacyCredentials = Boolean.parseBoolean(legacyCredentials);
        if (isLegacyCredentials) {
            logger.infov("User({0}) is legacy user. Try legacy process", user.getUsername());
            String legacyPasswordHash = user.getFirstAttribute("legacy_password_hash");
            String hash = DigestUtils.md5Hex(password);
            if (!hash.equals(legacyPasswordHash)) {
                return false;
            }

            logger.infov("User({0}) success to validate legacy process, Try to change password and remove legacy attribute", user.getUsername());

            // Find UserProvider to get UserModel, 'user' argument is just CachedUserModel, It can't be updated.
            // So, need to get UserModel(not cached) from UserProvider.
            RealmModel realmModel = context.getRealm();
            UserProvider userProvider = context.getSession().getProvider(UserProvider.class);
            UserModel newModel = userProvider.getUserById(realmModel, user.getId());

            // Change user password newly. it will be stored as keycloak provided hash(pbkdf2).
            newModel.credentialManager().updateCredential(UserCredentialModel.password(password));

            // Remove legacy attributes when after first legacy login process.
            newModel.removeAttribute("legacy_credentials");
            newModel.removeAttribute("legacy_password_hash");

            logger.infov("User({0}) success to change password and remove attributes", user.getUsername());
            return true;
        }
        return false;

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
