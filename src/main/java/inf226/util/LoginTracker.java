package inf226.util;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Counts login attempts, keeps track of how long an account is blocked after 10 failed attempts
 */
public final class LoginTracker {
    private static final int TIMEOUT = 10;
    private static final int ALLOWEDATTEMPTS = 10;

    public final int attempts;
    public final Maybe<Instant> blockedUntil;

    public LoginTracker() {
        this.attempts = 0;
        this.blockedUntil = Maybe.nothing();
    }

    public LoginTracker(int attempts){
        if(attempts < ALLOWEDATTEMPTS){
            this.attempts = attempts;
            this.blockedUntil = Maybe.nothing();
        }
        else {
            this.attempts = 0;
            blockedUntil = Maybe.just(Instant.now().plus(TIMEOUT, ChronoUnit.MINUTES));
        }
    }

    public LoginTracker increment(){
        return new LoginTracker(attempts + 1);
    }

    public boolean blocked(){
        try {
            return blockedUntil.get().compareTo(Instant.now()) > 0;
        } catch (Maybe.NothingException e) {
            return false;
        }
    }

    public LoginTracker clear(){
        return new LoginTracker(0);
    }

    //TODO
    public LoginTracker resetTimer() {
        return new LoginTracker(10);
    }
}

