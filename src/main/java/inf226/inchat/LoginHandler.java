package inf226.inchat;

import inf226.util.LoginTracker;
import inf226.util.Maybe;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

// Tracks login attempts for different accounts and sets a 10 minute cooldown after 10 failed login attempts
public final class LoginHandler {
    Map<UUID, LoginTracker> loginTrackerMap;

    public LoginHandler(){
        this.loginTrackerMap = new HashMap<>();
    }

    /**
     * Log in a user to the chat.
     */
    public boolean login(Account account, String password) {
        UUID identity = account.user.identity;
        loginTrackerMap.putIfAbsent(identity, new LoginTracker());
        LoginTracker tracker = loginTrackerMap.get(identity);

        // If timed out, reset timer and return false
        if(tracker.blocked()){
            loginTrackerMap.compute(identity, (k,v) -> v = v.resetTimer());
            try {
                System.err.println("Account " + identity.toString() + " blocked until " + loginTrackerMap.get(identity).blockedUntil.get().toString());
            } catch (Maybe.NothingException e) {
                System.err.println("Instant in LoginTracker failed");
            }
            return false;
        }
        // Correct password; clear tracker and return true
        if(account.checkPassword(password)) {
            loginTrackerMap.compute(identity, (k,v) -> v = v.clear());
            return true;
        }
        // Wrong password; increment tracker and return false
        loginTrackerMap.compute(identity, (k,v) -> v = v.increment());
        tracker = loginTrackerMap.get(identity);
        if(tracker.blocked()){
            try {
                System.err.println("Account " + identity.toString() + " blocked until " + loginTrackerMap.get(identity).blockedUntil.get().toString());
            } catch (Maybe.NothingException e) {
                System.err.println("Instant in LoginTracker failed");
            }
        }
        else {
            System.err.println("Account " + identity.toString() + " " + loginTrackerMap.get(identity).attempts + " failed login attempts");
        }
        return false;
    }

}
