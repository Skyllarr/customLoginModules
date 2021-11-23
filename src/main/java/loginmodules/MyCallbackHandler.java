package loginmodules;

import org.wildfly.security.evidence.PasswordGuessEvidence;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.security.Principal;

/**
 * The application implements the CallbackHandler.
 *
 * <p> This application is text-based.  Therefore it displays information
 * to the user using the OutputStreams System.out and System.err,
 * and gathers input from the user using the InputStream System.in.
 */
public class MyCallbackHandler implements CallbackHandler {

    private Principal principal;
    private char[] evidence;

    public MyCallbackHandler() {
    }

    /**
     * Sets this handler's state.
     *
     * @param principal the principal being authenticated.
     * @param evidence  the evidence being verified.
     */
    public void setSecurityInfo(final Principal principal, final Object evidence) {
        this.principal = principal;
        if (evidence instanceof PasswordGuessEvidence) {
            this.evidence = ((PasswordGuessEvidence) evidence).getGuess();
        }
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (callbacks == null)
            throw new IllegalArgumentException("The callbacks argument cannot be null");

        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback nameCallback = (NameCallback) callback;
                if (principal != null)
                    nameCallback.setName(this.principal.getName());
            } else if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                passwordCallback.setPassword((this.evidence));
            } else {
                throw new UnsupportedCallbackException(callback, "Unsupported callback");
            }
        }
    }
}
