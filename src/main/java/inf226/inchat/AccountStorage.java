package inf226.inchat;

import inf226.inchat.Account.Role;
import inf226.storage.DeletedException;
import inf226.storage.Storage;
import inf226.storage.Stored;
import inf226.storage.UpdatedException;
import inf226.util.Maybe;
import inf226.util.Maybe.NothingException;
import inf226.util.Mutable;
import inf226.util.Pair;
import inf226.util.Util;
import inf226.util.immutable.List;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

/**
 * This class stores accounts in the database.
 */
public final class AccountStorage
    implements Storage<Account,SQLException> {
    
    final Connection connection;
    final Storage<User,SQLException> userStore;
    final Storage<Channel,SQLException> channelStore;
   
    /**
     * Create a new account storage.
     *
     * @param  connection   The connection to the SQL database.
     * @param  userStore    The storage for User data.
     * @param  channelStore The storage for channels.
     */
    public AccountStorage(Connection connection,
                          Storage<User,SQLException> userStore,
                          Storage<Channel,SQLException> channelStore) 
      throws SQLException {
        this.connection = connection;
        this.userStore = userStore;
        this.channelStore = channelStore;
        
        connection.createStatement()
                .executeUpdate("CREATE TABLE IF NOT EXISTS Account (id TEXT PRIMARY KEY, version TEXT, user TEXT, key TEXT, FOREIGN KEY(user) REFERENCES User(id) ON DELETE CASCADE)");
        connection.createStatement()
                .executeUpdate("CREATE TABLE IF NOT EXISTS AccountChannel (account TEXT, channel TEXT, alias TEXT, ordinal INTEGER, role TEXT, PRIMARY KEY(account,channel), FOREIGN KEY(account) REFERENCES Account(id) ON DELETE CASCADE, FOREIGN KEY(channel) REFERENCES Channel(id) ON DELETE CASCADE)");
    }
    
    @Override
    public Stored<Account> save(Account account)
      throws SQLException {
        
        final Stored<Account> stored = new Stored<Account>(account);
        final PreparedStatement stmt = connection.prepareStatement("INSERT INTO Account VALUES(?,?,?,?)");
        stmt.setObject(1, stored.identity);
        stmt.setObject(2, stored.version);
        stmt.setObject(3, account.user.identity);
        stmt.setString(4, account.key.toString());
        stmt.execute();
        
        // Write the list of channels
        final Maybe.Builder<SQLException> exception = Maybe.builder();
        final Mutable<Integer> ordinal = new Mutable<Integer>(0);
        account.channels.forEach(element -> {
            String alias = element.first;
            Stored<Channel> channel = element.second;
            try {
                Role role = Util.lookup(account.roles, alias).get();
            	final PreparedStatement stmtb = connection.prepareStatement("INSERT INTO AccountChannel VALUES(?,?,?,?,?)");
            	//setObject, specify sqltype?
            	stmtb.setObject(1, stored.identity);
            	stmtb.setObject(2, channel.identity);
            	stmtb.setString(3, alias);
            	stmtb.setString(4,ordinal.get().toString());
            	stmtb.setObject(5, role);
            	stmtb.execute();
            }
            catch (SQLException e) { exception.accept(e) ; } catch (NothingException e) {
				System.err.println("Has no role for this channel!");
				e.printStackTrace();
			}
            ordinal.accept(ordinal.get() + 1);
        });

        Util.throwMaybe(exception.getMaybe());
        return stored;
    }
    
    @Override
    public synchronized Stored<Account> update(Stored<Account> account,
                                            Account new_account)
        throws UpdatedException,
            DeletedException,
            SQLException {
    final Stored<Account> current = get(account.identity);
    final Stored<Account> updated = current.newVersion(new_account);
    if(current.version.equals(account.version)) {
    	final PreparedStatement stmta = connection.prepareStatement("UPDATE Account SET (version,user) =(?,?) WHERE id =?");
    	stmta.setObject(1, updated.version);
    	stmta.setObject(2, new_account.user.identity);
    	stmta.setObject(3, updated.identity);
    	stmta.execute();
    	
    	
        //connection.createStatement().executeUpdate(sql);
        
        
        // Rewrite the list of channels    	
        final PreparedStatement stmtb = connection.prepareStatement("DELETE FROM AccountChannel WHERE account=?");
        stmtb.setObject(1, account.identity);
        stmtb.execute();
        final Maybe.Builder<SQLException> exception = Maybe.builder();
        final Mutable<Integer> ordinal = new Mutable<Integer>(0);
        new_account.channels.forEach(element -> {
            String alias = element.first;
            Stored<Channel> channel = element.second;
            try { 
                	Role role = Util.lookup(new_account.roles, alias).get();
	                final PreparedStatement stmtc = connection.prepareStatement("INSERT INTO AccountChannel VALUES(?,?,?,?,?)");
	                stmtc.setObject(1, account.identity);
	                stmtc.setObject(2, channel.identity);
	                stmtc.setString(3, alias);
	                stmtc.setString(4, ordinal.get().toString());
	                stmtc.setObject(5, role);
	            	stmtc.execute(); 
            	}
            catch (SQLException e) { exception.accept(e) ; } catch (NothingException e) {
				System.err.println("No role for that channel!");
				e.printStackTrace();
			}
            ordinal.accept(ordinal.get() + 1);
        });

        Util.throwMaybe(exception.getMaybe());
    } else {
        throw new UpdatedException(current);
    }
    return updated;
    }
   
    @Override
    public synchronized void delete(Stored<Account> account)
       throws UpdatedException,
              DeletedException,
              SQLException {
        final Stored<Account> current = get(account.identity);
        if(current.version.equals(account.version)) {
        final PreparedStatement stmt = connection.prepareStatement("DELETE FROM Account WHERE id =?");
        stmt.setObject(1, account.identity);
        stmt.execute();
        } else {
        throw new UpdatedException(current);
        }
    }
    @Override
    public Stored<Account> get(UUID id)
      throws DeletedException,
             SQLException {
    	final PreparedStatement accountstmt = connection.prepareStatement("SELECT version,user,key FROM Account WHERE id = ?");
    	accountstmt.setString(1, id.toString());
    	
    	final PreparedStatement channelstmt = connection.prepareStatement("SELECT channel,alias,ordinal,role FROM AccountChannel WHERE account = ? ORDER BY ordinal DESC");
    	channelstmt.setString(1, id.toString());

        final ResultSet accountResult = accountstmt.executeQuery();
        final ResultSet channelResult = channelstmt.executeQuery();

        if(accountResult.next()) {
            final UUID version = UUID.fromString(accountResult.getString("version"));
            final UUID userid =
            UUID.fromString(accountResult.getString("user"));
            final Stored<User> user = userStore.get(userid);

            final Password key = new Password(accountResult.getString("key"));

            // Get all the channels associated with this account
            final List.Builder<Pair<String,Stored<Channel>>> channels = List.builder();
            final List.Builder<Pair<String, Role>> roles = List.builder();
            while(channelResult.next()) {
                final UUID channelId = 
                    UUID.fromString(channelResult.getString("channel"));
                final String alias = channelResult.getString("alias");
                final Role role = Role.valueOf(channelResult.getString("role"));
                channels.accept(
                    new Pair<String,Stored<Channel>>(
                        alias,channelStore.get(channelId)));
                roles.accept(
            		new Pair<String,Role>(alias, role));
            }
            return (new Stored<Account>(new Account(user,channels.getList(),roles.getList(), key),id,version));
        } else {
            throw new DeletedException();
        }
    }
    
    /**
     * Look up an account based on their username.
     */
    public Stored<Account> lookup(String username)
      throws DeletedException,
             SQLException {
    	final PreparedStatement stmt = connection.prepareStatement("SELECT Account.id from Account INNER JOIN User ON user=User.id where User.name=?");
    	stmt.setString(1,username);

        System.err.println("lookup: " + stmt.toString());
        
        final ResultSet rs = stmt.executeQuery();
        if(rs.next()) {
            final UUID identity = 
                    UUID.fromString(rs.getString("id"));
            return get(identity);
        }
        throw new DeletedException();
    }
    
    
    /**
     * @param channelid a channels ID
     * @return a list of the members in the given channel
     * 
     * 
     * Should throw instead?
     */
    public List<Pair<String, Role>> memberlist(UUID channelid) {
		try {
			final PreparedStatement stmt = connection.prepareStatement("SELECT User.name, Account.role FROM AccountChannel INNER JOIN User ON Account.user = User.id   where id=?");
			stmt.setObject(1, channelid);
	        final ResultSet rs = stmt.executeQuery();
	        
	        final List.Builder<Pair<String, Role>> channels = List.builder();
	    	while(rs.next()) {
	    		String name = rs.getString("name");
	    		Role  role = Role.valueOf(rs.getString("role"));
	        	channels.accept(new Pair<String, Role>(name,role));
	    	}
	    	
	    	return channels.getList();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return List.empty();
    }
    
    /**
     * @param id of channel
     * @param role the role of the members you want to get
     * @return a list of the members with the @role in channel @id 
     */
    public List<String> getMembersWithRole(UUID id,Role role) {
    	List<Pair<String, Role>> members =  memberlist(id);
        final List.Builder<String> result = new List.Builder<String>();
        members.forEach(pair -> {
        if(pair.second.equals(role))
            result.accept(pair.first);
    	});
    	return result.getList();
    }
    
    /**
     * @param id
     * @return the amount of owners in the given channel @id
     */
    public int numOfOwners(UUID id) {
    	List<String> owners =  getMembersWithRole(id, Role.Owner);
    	return owners.length;
    }
    
} 
 
