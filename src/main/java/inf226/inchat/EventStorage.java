package inf226.inchat;

import inf226.storage.DeletedException;
import inf226.storage.Storage;
import inf226.storage.Stored;
import inf226.storage.UpdatedException;

import java.sql.*;
import java.time.Instant;
import java.util.UUID;




public final class EventStorage
    implements Storage<Channel.Event,SQLException> {
    
    private final Connection connection;
    
    public EventStorage(Connection connection) 
      throws SQLException {
        this.connection = connection;
        connection.createStatement()
                .executeUpdate("CREATE TABLE IF NOT EXISTS Event (id TEXT PRIMARY KEY, version TEXT, type INTEGER, time TEXT)");
        connection.createStatement()
                .executeUpdate("CREATE TABLE IF NOT EXISTS Message (id TEXT PRIMARY KEY, sender TEXT, content Text, FOREIGN KEY(id) REFERENCES Event(id) ON DELETE CASCADE)");
        connection.createStatement()
                .executeUpdate("CREATE TABLE IF NOT EXISTS Joined (id TEXT PRIMARY KEY, sender TEXT, FOREIGN KEY(id) REFERENCES Event(id) ON DELETE CASCADE)");
    }
    
    @Override
    public Stored<Channel.Event> save(Channel.Event event)
      throws SQLException {
        
        final Stored<Channel.Event> stored = new Stored<Channel.Event>(event);
        
        PreparedStatement stmt = connection.prepareStatement("INSERT INTO Event VALUES(?,?,?,?)");
        stmt.setObject(1, stored.identity);
        stmt.setObject(2, stored.version);
        stmt.setInt(3, event.type.code);
        stmt.setObject(4, event.time);

        stmt.execute();
        switch (event.type) {
            case message:
            	stmt = connection.prepareStatement("INSERT INTO Message VALUES(?,?,?)");
                stmt.setObject(1, stored.identity);
                stmt.setString(2, event.sender);
                stmt.setString(3, event.message);
                break;
            case join:
            	//XXX: Resource leak?
            	stmt = connection.prepareStatement("INSERT INTO Joined VALUES(?,?)");
                stmt.setObject(1, stored.identity);
                stmt.setString(2, event.sender);
                break;
        }
        stmt.execute();
        return stored;
    }
    
    @Override
    public synchronized Stored<Channel.Event> update(Stored<Channel.Event> event,
                                            Channel.Event new_event)
        throws UpdatedException,
            DeletedException,
            SQLException {
    final Stored<Channel.Event> current = get(event.identity);
    final Stored<Channel.Event> updated = current.newVersion(new_event);
    if(current.version.equals(event.version)) {

    	PreparedStatement stmt = connection.prepareStatement("UPDATE Event SET (version,time,type) = (?,?,?) WHERE id=?");
    	stmt.setObject(1, updated.version);
    	stmt.setObject(2, new_event.time);
    	stmt.setInt(3, new_event.type.code);
    	stmt.setObject(4, updated.identity);
    	stmt.execute();
        switch (new_event.type) {
            case message:
            	stmt = connection.prepareStatement("UPDATE Message SET (sender,content)=(?,?) WHERE id=?");
                stmt.setString(1, new_event.sender);
                stmt.setString(2, new_event.message);
                stmt.setObject(3, updated.identity);
                break;
            case join:
            	stmt = connection.prepareStatement("UPDATE Joined SET (sender)=? WHERE id=?");
                stmt.setString(1,new_event.sender);
                stmt.setObject(2, updated.identity);
                break;
        }
        stmt.execute();
    } else {
        throw new UpdatedException(current);
    }
        return updated;
    }
   
    @Override
    public synchronized void delete(Stored<Channel.Event> event)
       throws UpdatedException,
              DeletedException,
              SQLException {
        final Stored<Channel.Event> current = get(event.identity);
        if(current.version.equals(event.version)) {
	        final PreparedStatement stmt = connection.prepareStatement("DELETE FROM Event WHERE id =?");
	        stmt.setObject(1, event.identity);
	        stmt.execute();
        } else {
        throw new UpdatedException(current);
        }
    }
    @Override
    public Stored<Channel.Event> get(UUID id)
      throws DeletedException,
             SQLException {
    	final PreparedStatement stmt = connection.prepareStatement("SELECT version,time,type FROM Event WHERE id = ?");
    	stmt.setString(1, id.toString());
        final ResultSet rs = stmt.executeQuery();

        if(rs.next()) {
            final UUID version = UUID.fromString(rs.getString("version"));
            final Channel.Event.Type type = 
                Channel.Event.Type.fromInteger(rs.getInt("type"));
            final Instant time = 
                Instant.parse(rs.getString("time"));
            
            final Statement mstatement = connection.createStatement();
            switch(type) {
                case message:
                	final PreparedStatement stmtb = connection.prepareStatement("SELECT sender,content FROM Message WHERE id = ?");
                	stmtb.setString(1, id.toString());
                    final ResultSet mrs = stmtb.executeQuery();
                    mrs.next();
                    return new Stored<Channel.Event>(
                            Channel.Event.createMessageEvent(time,mrs.getString("sender"),mrs.getString("content")),
                            id,
                            version);
                case join:
                	final PreparedStatement stmtc = connection.prepareStatement("SELECT sender FROM Joined WHERE id = ?");
                	stmtc.setString(1, id.toString());
                    final ResultSet ars = stmtc.executeQuery();
                    ars.next();
                    return new Stored<Channel.Event>(
                            Channel.Event.createJoinEvent(time,ars.getString("sender")),
                            id,
                            version);
            }
        }
        throw new DeletedException();
    }
    
}


 
