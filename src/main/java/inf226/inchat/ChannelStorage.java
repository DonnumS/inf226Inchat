package inf226.inchat;

import inf226.storage.DeletedException;
import inf226.storage.Storage;
import inf226.storage.Stored;
import inf226.storage.UpdatedException;
import inf226.util.Maybe;
import inf226.util.Mutable;
import inf226.util.Pair;
import inf226.util.Util;
import inf226.util.immutable.List;

import java.sql.*;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * This class stores Channels in a SQL database.
 */
public final class ChannelStorage
    implements Storage<Channel,SQLException> {
    
    final Connection connection;
    /* The waiters object represent the callbacks to
     * make when the channel is updated.
     */
    private Map<UUID,List<Consumer<Stored<Channel>>>> waiters
        = new TreeMap<UUID,List<Consumer<Stored<Channel>>>>();
    public final EventStorage eventStore;
    
    public ChannelStorage(Connection connection,
                          EventStorage eventStore) 
      throws SQLException {
        this.connection = connection;
        this.eventStore = eventStore;
        
        connection.createStatement()
                .executeUpdate("CREATE TABLE IF NOT EXISTS Channel (id TEXT PRIMARY KEY, version TEXT, name TEXT)");
        connection.createStatement()
                .executeUpdate("CREATE TABLE IF NOT EXISTS ChannelEvent (channel TEXT, event TEXT, ordinal INTEGER, PRIMARY KEY(channel,event), FOREIGN KEY(channel) REFERENCES Channel(id) ON DELETE CASCADE, FOREIGN KEY(event) REFERENCES Event(id) ON DELETE CASCADE)");
    }
    
    @Override
    public Stored<Channel> save(Channel channel)
      throws SQLException {
        
        final Stored<Channel> stored = new Stored<Channel>(channel);
        final PreparedStatement stmt = connection.prepareStatement("INSERT INTO Channel VALUES(?,?,?)");
        stmt.setObject(1, stored.identity);
        stmt.setObject(2, stored.version);
        stmt.setString(3, channel.name);
        stmt.execute();
        // Write the list of events
        final Maybe.Builder<SQLException> exception = Maybe.builder();
        final Mutable<Integer> ordinal = new Mutable<Integer>(0);
        channel.events.forEach(event -> {
            try { 
	            	final PreparedStatement stmtb = connection.prepareStatement("INSERT INTO ChannelEvent VALUES(?,?,?)");
	            	stmtb.setObject(1, stored.identity);
	            	stmtb.setObject(2,event.identity);
	            	stmtb.setString(3, ordinal.get().toString());
	            	stmtb.execute();
        		}
            catch (SQLException e) { 
            		exception.accept(e) ; }
            ordinal.accept(ordinal.get() + 1);
        });

        Util.throwMaybe(exception.getMaybe());
        return stored;
    }
    
    @Override
    public synchronized Stored<Channel> update(Stored<Channel> channel,
                                            Channel new_channel)
        throws UpdatedException,
            DeletedException,
            SQLException {
        final Stored<Channel> current = get(channel.identity);
        final Stored<Channel> updated = current.newVersion(new_channel);
        if(current.version.equals(channel.version)) {

        	final PreparedStatement stmt = connection.prepareStatement("UPDATE Channel SET (version,name) =(?,?) WHERE id=?");
        	stmt.setObject(1, updated.version);
        	stmt.setString(2, new_channel.name);
        	stmt.setObject(3, updated.identity);
        	stmt.execute();
            
            
            // Rewrite the list of events
        	final PreparedStatement stmtb = connection.prepareStatement("DELETE FROM ChannelEvent WHERE channel=?");
        	stmtb.setObject(1, channel.identity);
        	stmtb.execute();
        	
            final Maybe.Builder<SQLException> exception = Maybe.builder();
            final Mutable<Integer> ordinal = new Mutable<Integer>(0);
            new_channel.events.forEach(event -> {            	
                try {
                	final PreparedStatement stmtc = connection.prepareStatement("INSERT INTO ChannelEvent VALUES(?,?,?)");
                	stmtc.setObject(1, channel.identity);
                	stmtc.setObject(2, event.identity);
                	stmtc.setString(3, ordinal.get().toString());
                	stmtc.execute();
                }
                catch (SQLException e) { exception.accept(e) ; }
                ordinal.accept(ordinal.get() + 1);
            });

            Util.throwMaybe(exception.getMaybe());
        } else {
            throw new UpdatedException(current);
        }
        giveNextVersion(updated);
        return updated;
    }
   
    @Override
    public synchronized void delete(Stored<Channel> channel)
       throws UpdatedException,
              DeletedException,
              SQLException {
        final Stored<Channel> current = get(channel.identity);
        if(current.version.equals(channel.version)) {
        final PreparedStatement stmt = connection.prepareStatement("DELETE FROM Channel WHERE id =?");
        stmt.setObject(1, channel.identity);
        stmt.execute();
        } else {
        throw new UpdatedException(current);
        }
    }
    @Override
    public Stored<Channel> get(UUID id)
      throws DeletedException,
             SQLException {
    	final PreparedStatement channelstmt = connection.prepareStatement("SELECT version,name FROM Channel WHERE id = ?");
    	final PreparedStatement eventstmt = connection.prepareStatement("SELECT event,ordinal FROM ChannelEvent WHERE channel = ? ORDER BY ordinal DESC");
    	channelstmt.setString(1, id.toString());
    	eventstmt.setString(1, id.toString());

        final ResultSet channelResult = channelstmt.executeQuery();
        final ResultSet eventResult = eventstmt.executeQuery();

        if(channelResult.next()) {
            final UUID version = 
                UUID.fromString(channelResult.getString("version"));
            final String name =
                channelResult.getString("name");
            // Get all the events associated with this channel
            final List.Builder<Stored<Channel.Event>> events = List.builder();
            while(eventResult.next()) {
                final UUID eventId = UUID.fromString(eventResult.getString("event"));
                events.accept(eventStore.get(eventId));
            }
            return (new Stored<Channel>(new Channel(name,events.getList()),id,version));
        } else {
            throw new DeletedException();
        }
    }
    
    /**
     * This function creates a "dummy" update.
     * This function should be called when events are changed or
     * deleted from the channel.
     */
    public Stored<Channel> noChangeUpdate(UUID channelId)
        throws SQLException, DeletedException {
    	final PreparedStatement stmt = connection.prepareStatement("UPDATE Channel SET (version) = ? WHERE id= ?");
        stmt.setObject(1, UUID.randomUUID());
        stmt.setObject(2, channelId);
        stmt.execute();
        Stored<Channel> channel = get(channelId);
        giveNextVersion(channel);
        return channel;
    }
    
    /**
     * Get the current version UUID for the specified channel.
     * @param id UUID for the channel.
     */
    public UUID getCurrentVersion(UUID id)
      throws DeletedException,
             SQLException {
    	final PreparedStatement stmt = connection.prepareStatement( "SELECT version FROM Channel WHERE id = ?");
        stmt.setString(1, id.toString());

        final ResultSet channelResult = stmt.executeQuery();
        if(channelResult.next()) {
            return UUID.fromString(
                    channelResult.getString("version"));
        }
        throw new DeletedException();
    }
    
    /**
     * Wait for a new version of a channel.
     * This is a blocking call to get the next version of a channel.
     * @param identity The identity of the channel.
     * @param version  The previous version accessed.
     * @return The newest version after the specified one.
     */
    public Stored<Channel> waitNextVersion(UUID identity, UUID version)
      throws DeletedException,
             SQLException {
        Maybe.Builder<Stored<Channel>> result
            = Maybe.builder();
        // Insert our result consumer
        synchronized(waiters) {
            Maybe<List<Consumer<Stored<Channel>>>> channelWaiters 
                = Maybe.just(waiters.get(identity));
            waiters.put(identity,List.cons(result,channelWaiters.defaultValue(List.empty())));
        }
        // Test if there already is a new version avaiable
        if(!getCurrentVersion(identity).equals( version)) {
            return get(identity);
        }
        // Wait
        synchronized(result) {
            while(true) {
                try {
                    result.wait();
                    return result.getMaybe().get();
                } catch (InterruptedException e) {
                    System.err.println("Thread interrupted.");
                } catch (Maybe.NothingException e) {
                    // Still no result, looping
                }
            }
        }
    }
    
    /**
     * Notify all waiters of a new version
     */
    private void giveNextVersion(Stored<Channel> channel) {
        synchronized(waiters) {
            Maybe<List<Consumer<Stored<Channel>>>> channelWaiters 
                = Maybe.just(waiters.get(channel.identity));
            try {
                channelWaiters.get().forEach(w -> {
                    w.accept(channel);
                    synchronized(w) {
                        w.notifyAll();
                    }
                });
            } catch (Maybe.NothingException e) {
                // No were waiting for us :'(
            }
            waiters.put(channel.identity,List.empty());
        }
    }
    
    public List<Pair<String, UUID>> getChannels(){
    	try {
    		//                .executeUpdate("CREATE TABLE IF NOT EXISTS Channel (id TEXT PRIMARY KEY, version TEXT, name TEXT)");
			final String sql = "SELECT id, name FROM Channel";

	        final Statement stmt = connection.createStatement();

	        final ResultSet rs = stmt.executeQuery(sql);
	        
            final List.Builder<Pair<String, UUID>> channels = List.builder();
        	while(rs.next()) {
        		String alias = rs.getString("name");
        		UUID id = UUID.fromString(rs.getString("id"));
	        	channels.accept(new Pair<String, UUID>(alias,id));
        	}
        	
        	return channels.getList();

		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return List.empty();
    }
    
    public boolean channelExist(String alias) {
		List<Pair<String, UUID>> channels = getChannels();
		if(Util.lookup(channels, alias).isNothing()) {
			return false;
		} else {
	    	return true;
		}
    }
    
    /**
     * Get the channel belonging to a specific event.
     */
    public Stored<Channel> lookupChannelForEvent(Stored<Channel.Event> e)
      throws SQLException, DeletedException {
    	final PreparedStatement stmt = connection.prepareStatement("SELECT channel FROM ChannelEvent WHERE event=?");
        stmt.setObject(1, e.identity);
        final ResultSet rs = stmt.executeQuery();
        
        if(rs.next()) {
            final UUID channelId = UUID.fromString(rs.getString("channel"));
            return get(channelId);
        }
        throw new DeletedException();
    }
} 
 
 
