package inf226.inchat;

import inf226.storage.DeletedException;
import inf226.storage.Storage;
import inf226.storage.Stored;
import inf226.storage.UpdatedException;
import inf226.util.Maybe;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.UUID;



/**
 * The UserStore stores User objects in a SQL database.
 */
public final class UserStorage
    implements Storage<User,SQLException> {
    
    final Connection connection;
    
    public UserStorage(Connection connection) 
      throws SQLException {
        this.connection = connection;
        connection.createStatement()
                .executeUpdate("CREATE TABLE IF NOT EXISTS User (id TEXT PRIMARY KEY, version TEXT, name TEXT, joined TEXT)");
    }
    
    @Override
    public Stored<User> save(User user)
      throws SQLException {
        final Stored<User> stored = new Stored<User>(user);
        final PreparedStatement stmt = connection.prepareStatement( "INSERT INTO User VALUES(?,?,?,?)");
        //setObject specify sqltype?
        stmt.setObject(1,stored.identity);
        stmt.setObject(2, stored.version);
        stmt.setString(3, user.name.toString());
        stmt.setString(4, user.joined.toString());
        stmt.execute();
        return stored;
    }
    
    @Override
    public synchronized Stored<User> update(Stored<User> user,
                                            User new_user)
        throws UpdatedException,
            DeletedException,
            SQLException {
        final Stored<User> current = get(user.identity);
        final Stored<User> updated = current.newVersion(new_user);
        if(current.version.equals(user.version)) {
	        final PreparedStatement stmt = connection.prepareStatement("UPDATE User SET (version,name,joined) =(?,?,?) WHERE id=?");
	        stmt.setObject(1, updated.version);
	        stmt.setString(2, new_user.name.toString());
	        stmt.setString(3, new_user.joined.toString());
	        stmt.setObject(4, updated.identity);
	        stmt.execute();
        } else {
            throw new UpdatedException(current);
        }
        return updated;
    }
   
    @Override
    public synchronized void delete(Stored<User> user)
       throws UpdatedException,
              DeletedException,
              SQLException {
        final Stored<User> current = get(user.identity);
        if(current.version.equals(user.version)) {
        	final PreparedStatement stmt = connection.prepareStatement("DELETE FROM User WHERE id =?");
        	stmt.setObject(1, user.identity);
        	stmt.execute();
        } else {
        throw new UpdatedException(current);
        }
    }
    @Override
    public Stored<User> get(UUID id)
      throws DeletedException,
             SQLException {
    	final PreparedStatement stmt = connection.prepareStatement("SELECT version,name,joined FROM User WHERE id = ?");
    	stmt.setString(1, id.toString());
        final ResultSet rs = stmt.executeQuery();

        if(rs.next()) {
            final UUID version = 
                UUID.fromString(rs.getString("version"));
            final String name = rs.getString("name");
            final Instant joined = Instant.parse(rs.getString("joined"));
            return (new Stored<User>
                        (new User(name,joined),id,version));
        } else {
            throw new DeletedException();
        }
    }
    
    /**
     * Look up a user by their username;
     **/
    public Maybe<Stored<User>> lookup(String name) {
        try{
        	final PreparedStatement stmt = connection.prepareStatement("SELECT id FROM User WHERE name = ?");
        	stmt.setString(1, name);
            final ResultSet rs = stmt.executeQuery();
            if(rs.next())
                return Maybe.just(
                    get(UUID.fromString(rs.getString("id"))));
        } catch (Exception e) {
        
        }
        return Maybe.nothing();
    }
}


