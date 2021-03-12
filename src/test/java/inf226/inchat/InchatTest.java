 
package inf226.inchat;

import org.junit.jupiter.api.Test;

import inf226.storage.*;

import inf226.util.*;

import java.util.UUID;
import java.sql.SQLException;
import java.sql.Connection;
import java.sql.DriverManager;

public class InchatTest{
    @Test
    void chatSetup() throws Maybe.NothingException,SQLException {
        UUID testID = UUID.randomUUID();
        System.err.println("Running test:" + testID);
        final String path = "test" + testID +  ".db";
        final String dburl = "jdbc:sqlite:" + path;
        final Connection connection = DriverManager.getConnection(dburl);
        connection.createStatement().executeUpdate("PRAGMA foreign_keys = ON");
        UserStorage userStore
            = new UserStorage(connection);
        EventStorage eventStore
            = new EventStorage(connection);
        ChannelStorage channelStore
            = new ChannelStorage(connection,eventStore);
        AccountStorage accountStore
            = new AccountStorage(connection,userStore,channelStore);
        SessionStorage sessionStore
            = new SessionStorage(connection,accountStore);
        InChat inchat = new InChat(userStore,channelStore,accountStore,sessionStore);
        Stored<Session> aliceSession = inchat.register("Alice","badpassword").get();
        inchat.register("Bob","worse").get();
        Stored<Session> bobSession = inchat.login("Bob","worse").get();
        Stored<Channel> channel = inchat.createChannel(aliceSession.value.account,"Awesome").get();
        inchat.postMessage(aliceSession.value.account,channel, "Test message.").get();
        inchat.joinChannel(bobSession.value.account,channel.identity).get();
    }
    
    /*
     * Make tests for creating accounts, checking valid passwords. and logging in / out
     * Creating channels, checking for non-duplicates etc.
     * 
     * 
     * */
}
