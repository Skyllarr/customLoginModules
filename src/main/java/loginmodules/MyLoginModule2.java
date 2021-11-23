package loginmodules;

import org.wildfly.security.auth.principal.NamePrincipal;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * A {@link LoginModule} implementation used in the JAAS security realm tests. It uses a static
 * map of username -> password to determine if a login is successful or not.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class MyLoginModule2 implements LoginModule {

    private final Map<String, char[]> usersMap = new HashMap<String, char[]>();
    private Principal principal;
    private Subject subject;
    private CallbackHandler handler;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.handler = callbackHandler;
        this.usersMap.put("javajoe", "$#21pass".toCharArray());
        this.usersMap.put("javaduke", "dukepass!@34".toCharArray());
    }

    @Override
    public boolean login() throws LoginException {
        // obtain the incoming username and password from the callback handler
        NameCallback nameCallback = new NameCallback("Username");
        PasswordCallback passwordCallback = new PasswordCallback("Password", false);
        Callback[] callbacks = new Callback[]{nameCallback, passwordCallback};
        try {
            this.handler.handle(callbacks);
        } catch(UnsupportedCallbackException | IOException e) {
            throw new LoginException("Error handling callback: " + e.getMessage());
        }

        final String username = nameCallback.getName();
        this.principal = new NamePrincipal(username);
        final char[] password = passwordCallback.getPassword();

        char[] storedPassword = this.usersMap.get(username);
        if (!Arrays.equals(storedPassword, password)) {
            throw new LoginException("");
        } else {
            return true;
        }
    }

    @Override
    public boolean commit() throws LoginException {
//        Roles callerPrincipal = new Roles("CallerPrincipal");
//        callerPrincipal.addMember(principal);
//        this.subject.getPrincipals().add(callerPrincipal);
        this.subject.getPrincipals().add(new NamePrincipal("whoami"));
        Roles roles = new Roles("Admin");
        this.subject.getPrincipals().add(roles);

        Roles roles2 = new Roles("User");
        this.subject.getPrincipals().add(roles2);

        Roles roles3 = new Roles("Guest");
        this.subject.getPrincipals().add(roles3);
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        this.subject.getPrincipals().clear();
        return true;
    }

    private static class Roles implements Principal{

        private final String name;

        private final Set<String> roles;

        Roles(final String name) {
            this.name = name;
            this.roles = new HashSet<>();
        }

        public String getName() {
            return this.name;
        }
    }
}
