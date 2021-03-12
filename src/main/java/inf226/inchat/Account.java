package inf226.inchat;

import inf226.storage.Stored;
import inf226.util.Maybe;
import inf226.util.Pair;
import inf226.util.Util;
import inf226.util.immutable.List;

/**
 * The Account class holds all information private to
 * a specific user.
 **/
public final class Account {
    /*
     * A channel consists of a User object of public account info,
     * and a list of channels which the user can post to.
     * 
     */
	static enum Role {
		Banned,
		Observer,
		Participant,
		Moderator,
		Owner
	}
    public final Stored<User> user;
    public final List<Pair<String,Stored<Channel>>> channels;
    public final List<Pair<String, Role>> roles;
    public final Password key; //Hashed password from KDF
    
    public Account(Stored<User> user, 
                   List<Pair<String,Stored<Channel>>> channels,List<Pair<String, Role>> roles,
                   Password key) {
        this.user = user;
        this.channels = channels;
        this.key = key;
        this.roles = roles;
    }
    
    /**
     * Create a new Account.
     *
     * @param user The public User profile for this user.
     * @param password The login password for this account.
     **/
    public static Account create(Stored<User> user,
                                 String password) {
    	Password key = Password.createPassword(password);
        return new Account(user,List.empty(), List.empty(), key);
    }
    
    /**
     * Join a channel with this account.
     *
     * @return A new account object with the channel added.
     */
    public Account joinChannel(String alias, Stored<Channel> channel, Role role) {
        Pair<String,Stored<Channel>> entry
            = new Pair<String,Stored<Channel>>(alias,channel);
        Pair<String, Role> entryRole = new Pair<String, Role>(alias, role);
        return new Account
                (user,
                 List.cons(entry,
                           channels), List.cons(entryRole, roles),
                 key);
    }
    
    /**
     * @param alias of the channel
     * @param role the new role of this account
     * @return a new account that is identical to this one, except it has a new list of channels with its new role.
     */
    public Account setRole(String alias, Role role) {
    	final List.Builder<Pair<String,Role>> new_roles = List.builder();
    	roles.forEach(element ->{
    		//System.err.println("Channel: " + element.first + " Role: " + element.second + " Alias: " + alias);
    		if(element.first.equals(alias)) {
    			//System.err.println("Changing a role");
    			new_roles.accept(new Pair<String,Role>(alias,role));
    		} else {
    			new_roles.accept(element);
    		}
    	});
	    return new Account(user,channels, new_roles.getList(),key);
    }
    
    /**
     * @param alias of the channel
     * @return the role this account has in the given channel.
     */
    public Maybe<Role> getRole(String alias) {
		Maybe<Role> role = Util.lookup(roles, alias);
		return role;

    }



    /**
     * Check weather if a string is a correct password for
     * this account.
     *
     * @return true if password matches.
     */
    public boolean checkPassword(String password) {
        return this.key.check(password);
    }
    
    public String getName() {
    	return user.value.name.toString();
    }
}
