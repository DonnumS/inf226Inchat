package inf226.inchat;

import inf226.storage.DeletedException;
import inf226.storage.Storage;
import inf226.storage.Stored;
import inf226.storage.UpdatedException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.UUID;

/**
 * The SessionStorage stores Session objects in a SQL database.
 */
public final class SessionStorage
    implements Storage<Session,SQLException> {
    
    final Connection connection;
    final Storage<Account,SQLException> accountStorage;
    
    public SessionStorage(Connection connection,
                          Storage<Account,SQLException> accountStorage)
      throws SQLException {
        this.connection = connection;
        this.accountStorage = accountStorage;
        connection.createStatement()
                .executeUpdate("CREATE TABLE IF NOT EXISTS Session (id TEXT PRIMARY KEY, version TEXT, account TEXT, expiry TEXT, FOREIGN KEY(account) REFERENCES Account(id) ON DELETE CASCADE)");
    }
    
    @Override
    public Stored<Session> save(Session session)
      throws SQLException {
        
        final Stored<Session> stored = new Stored<Session>(session);
        
        final PreparedStatement stmt = connection.prepareStatement("INSERT INTO Session VALUES(?,?,?,?)");
        stmt.setObject(1, stored.identity);
        stmt.setObject(2, stored.version);
        stmt.setObject(3, session.account.identity);
        stmt.setString(4, session.expiry.toString());
        stmt.execute();
        return stored;
    }
    
    @Override
    public synchronized Stored<Session> update(Stored<Session> session,
                                            Session new_session)
        throws UpdatedException,
            DeletedException,
            SQLException {
    final Stored<Session> current = get(session.identity);
    final Stored<Session> updated = current.newVersion(new_session);
    if(current.version.equals(session.version)) {
    	final PreparedStatement stmt = connection.prepareStatement("UPDATE Session SET (version,account,expiry) =(?,?,?) WHERE id=?");
    	stmt.setObject(1, updated.version);
    	stmt.setObject(2, new_session.account.identity);
    	stmt.setString(3, new_session.expiry.toString());
    	stmt.setObject(4, updated.identity);
    	stmt.execute();
    } else {
        throw new UpdatedException(current);
    }
    return updated;
    }
   
    @Override
    public synchronized void delete(Stored<Session> session)
       throws UpdatedException,
              DeletedException,
              SQLException {
        final Stored<Session> current = get(session.identity);
        if(current.version.equals(session.version)) {
        final PreparedStatement stmt = connection.prepareStatement("DELETE FROM Session WHERE id = ?");
        //setObject, specify sqltype?
        stmt.setObject(1, session.identity);
        stmt.execute();
        } else {
        throw new UpdatedException(current);
        }
    }
    @Override
    public Stored<Session> get(UUID id)
      throws DeletedException,
             SQLException {
    	final PreparedStatement stmt = connection.prepareStatement("SELECT version,account,expiry FROM Session WHERE id = ?");
    	stmt.setString(1, id.toString());
        final ResultSet rs = stmt.executeQuery();

        if(rs.next()) {
            final UUID version = UUID.fromString(rs.getString("version"));
            final Stored<Account> account
               = accountStorage.get(
                    UUID.fromString(rs.getString("account")));
            final Instant expiry = Instant.parse(rs.getString("expiry"));
            return (new Stored<Session>
                        (new Session(account,expiry),id,version));
        } else {
            throw new DeletedException();
        }
    }
    
    
} 
