package inf226.inchat;

import inf226.inchat.Account.Role;
import inf226.storage.Stored;
import inf226.util.Maybe;
import inf226.util.Mutable;
import inf226.util.Util;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.owasp.encoder.Encode;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * The Hanlder class handles all HTTP and HTML components.
 * Functions called display⋯ and print⋯ output HTML.
 */

public class Handler extends AbstractHandler
{
  // Static resources:
  private final File style = new File("style.css");
  private final File login = new File("login.html");
  private final File register = new File("register.html");
  private final File landingpage = new File("index.html");
  private final File script = new File("script.js");

  private static InChat inchat;
  
  private final DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm (z)")
                                 .withZone( ZoneId.systemDefault() );

  
  /**
   * This is the entry point for HTTP requests.
   * Some requests require login, while some can be processed
   * without a valid session.
   */
  public void handle(String target,
                     Request baseRequest,
                     HttpServletRequest request,
                     HttpServletResponse response)
    throws IOException, ServletException
  {
    System.err.println("Got a request for \"" + target + "\"");
    final Map<String,Cookie> cookies = getCookies(request);
    //CSP For every site on our page.
    response.addHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'none';");
    response.addHeader("X-Frame-Options", "DENY");

    // Pages which do not require login
    if (target.equals("/style.css")) {
        serveFile(response,style,"text/css;charset=utf-8");
        baseRequest.setHandled(true);
        return;
    } else if (target.equals("/login")) {
        serveFile(response,login, "text/html;charset=utf-8");
        baseRequest.setHandled(true);
        return;
    } else if (target.equals("/register")) {
        serveFile(response,register, "text/html;charset=utf-8");
        baseRequest.setHandled(true);
        return;
    }else if (target.equals("/script.js")) {
        serveFile(response,script, "application/javascript");
        baseRequest.setHandled(true);
        return;
    }
    
    // Attempt to create a session
    
    Maybe.Builder<Stored<Session>> sessionBuilder
        = new Maybe.Builder<Stored<Session>>();
    
    if(request.getParameter("register") != null) {
        // Try to register a new user:
        System.err.println("User registration.");
        try {
            String username = (new Maybe<String>
                (request.getParameter("username"))).get();
            String password = (new Maybe<String>
                (request.getParameter("password"))).get();
            String retypePassword = (new Maybe<String>
                    (request.getParameter("password_repeat"))).get();

            if(UserName.validUsername(username) && Password.validPassword(password) && password.equals(retypePassword)) {
                System.err.println("Registering user: \"" + username
                             + "\" with password \"" + password + "\"");
                inchat.register(username,password).forEach(sessionBuilder);
            } else {
            	//Crazy good UX
            	response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            	PrintWriter test = response.getWriter();
                test.println("Failed to create user. Use a NIST approved password and a username with letters, numbers, dash(-) and underscore(_).");
                test.close();
            }
        } catch (Maybe.NothingException e) {
            // Not enough data suppied for login
            System.err.println("Broken usage of register");
        }
    } else if(request.getParameter("login") != null) {
        // Login for an existing user
        System.err.println("Trying to log in as:");
        try {
            final String username = (new Maybe<String>
                (request.getParameter("username"))).get();
            System.err.println("Username: " + username);
            final String password = (new Maybe<String>
                (request.getParameter("password"))).get();

            if(UserName.validUsername(username) && Password.validPassword(password))
                inchat.login(username, password).forEach(sessionBuilder);
        } catch (Maybe.NothingException e) {
            // Not enough data suppied for login
            System.err.println("Broken usage of login");
        }
    
    } else {
        // Final option is to restore a session from a cookie
        System.err.println("Final option is to restore a session from a cookie (line 125)");
        final Maybe<Cookie> sessionCookie
            = new Maybe<Cookie>(cookies.get("session"));
        final Maybe<Stored<Session>> cookieSession
            =  sessionCookie.bind(c -> 
                    inchat.restoreSession(UUID.fromString(c.getValue())));
        cookieSession.forEach(sessionBuilder);
        
    }
    response.setContentType("text/html;charset=utf-8");
    
    try {
        final Stored<Session> session = sessionBuilder.getMaybe().get();
        final Stored<Account> account = session.value.account;
        // User is now logged in with a valid sesion.
        // We set the session cookie to keep the user logged in:
        //Cookie cookie = new Cookie("session",session.identity.toString());
        //cookie.setHttpOnly(true);
        //cookie.setSecure(true);
        //cookie.setComment(SAME_SITE_STRICT_COMMENT); //this works if we import import static org.eclipse.jetty.http.HttpCookie.SAME_SITE_STRICT_COMMENT;
        //response.addCookie(cookie);
        //setHeader will overwrite any other set-cookie headers. Use addHeader if that will be an issue.
        //Could add ; Secure to the setHeader.

        response.setHeader("Set-Cookie", "session=" + session.identity.toString() + "; HttpOnly; SameSite=strict");
        final Maybe<Cookie> sessionCookie
            = new Maybe<Cookie>(cookies.get("session"));
        String antiCSRF = sessionCookie.get().getValue();
        System.err.println("token: " + antiCSRF);
        final PrintWriter out = response.getWriter();
        // Handle a logged in request.
        try {
            if(target.startsWith("/channel/")) {
                final String alias
                    = target.substring(("/channel/").length());
                
                // Resolve channel within the current session
                Stored<Channel> channel =
                    Util.lookup(account.value.channels,alias).get();
                System.err.println(request.getParameter("token"));
                if(request.getMethod().equals("POST") && request.getParameter("token").equals(antiCSRF)) {
                    // This is a request to post something in the channel.
                    System.err.println(request.getParameter("token"));
                    System.err.println(antiCSRF);
                    if(request.getParameter("newmessage") != null) {
                        String message = (new Maybe<String>
                            (request.getParameter("message"))).get();
                        channel = inchat.postMessage(account,channel,message).get();
                    }
                    
                    if(request.getParameter("deletemessage") != null) {
                        UUID messageId = 
                            UUID.fromString(Maybe.just(request.getParameter("message")).get());
                        Stored<Channel.Event> message = inchat.getEvent(messageId).get();
                        channel = inchat.deleteEvent(account,channel, message);
                    }
                    if(request.getParameter("editmessage") != null) {
                        String message = (new Maybe<String>
                            (request.getParameter("content"))).get();
                        UUID messageId = 
                            UUID.fromString(Maybe.just(request.getParameter("message")).get());
                        Stored<Channel.Event> event = inchat.getEvent(messageId).get();
                        channel = inchat.editMessage(account, channel, event, message);
                    }
                    
                    if(request.getParameter("setpermission") != null) {
                    	String username = (new Maybe<String>(request.getParameter("username"))).get();
                    	String role = (new Maybe<String>(request.getParameter("role"))).get();
                    	System.err.println("username: " + username + "\nrole: " + role);
                    	channel = inchat.setRole(account, username, role, channel);
                    	//set role function
                    }
                }
                
                out.println("<!DOCTYPE html>");
                out.println("<html lang=\"en-GB\">");
                printStandardHead(out, "inChat: " + alias);
                out.println("<body>");
                printStandardTop(out,  "inChat: " + alias);
                out.println("<div class=\"main\">");
                printChannelList(out, account.value, alias);
                printChannel(out, channel, alias, antiCSRF);
                out.println("</div>");
                out.println("</body>");
                out.println("</html>");
                response.setStatus(HttpServletResponse.SC_OK);
                baseRequest.setHandled(true);
                return ;
            }
            
            if(target.startsWith("/create")) {
                out.println("<!DOCTYPE html>");
                out.println("<html lang=\"en-GB\">");
                printStandardHead(out, "inChat: Create a new channel!");
                out.println("<body>");
                printStandardTop(out,  "inChat: Create a new channel!");
                
                out.println("<form class=\"login\" action=\"/\" method=\"POST\">"
                  + "<div class=\"name\"><input type=\"text\" name=\"channelname\" placeholder=\"Channel name\"></div>"
                  + "<div class=\"submit\"><input type=\"submit\" name=\"createchannel\" value=\"Create Channel\"></div>"
                  + "<div><input type=\"hidden\" name=\"token\" value=\"" + antiCSRF + "\"/></div>"
                  + "</form>");
                out.println("</body>");
                out.println("</html>");
                response.setStatus(HttpServletResponse.SC_OK);
                baseRequest.setHandled(true);
                return ;
                
            }
            if(target.equals("/joinChannel")) {
                out.println("<!DOCTYPE html>");
                out.println("<html lang=\"en-GB\">");
                printStandardHead(out, "inChat: " + account.value.user.value.name);
                out.println("<body>");
                printStandardTop(out, "inChat – Join a channel!");
                
                out.println("<form class=\"login\" action=\"/join\" method=\"POST\">"
                  + "<div class=\"name\"><input type=\"text\" name=\"channelid\" placeholder=\"Channel ID number:\"></div>"
                  + "<div class=\"submit\"><input type=\"submit\" name=\"joinchannel\" value=\"Join channel\"></div>"
                  + "<div><input type=\"hidden\" name=\"token\" value=\"" + antiCSRF + "\"/></div>"
                  + "</form>");
                out.println("</body>");
                out.println("</html>");
                response.setStatus(HttpServletResponse.SC_OK);
                baseRequest.setHandled(true);
                return ;
            }

            if(target.startsWith("/editMessage")) {
                String alias = (new Maybe<String>
                        (request.getParameter("channelname"))).get();
                String messageid = (new Maybe<String>
                        (request.getParameter("message"))).get();
                String originalContent = (new Maybe<String>
                        (request.getParameter("originalcontent"))).get();
                out.println("<!DOCTYPE html>");
                out.println("<html lang=\"en-GB\">");
                printStandardHead(out, "inChat: Edit message");
                out.println("<body>");
                printStandardTop(out,  "inChat: Edit message");
                out.println("<script src=\"/script.js\"></script>");
                
                out.println("<form class=\"entry\" action=\"/channel/" + Encode.forHtmlAttribute(alias) + "\" method=\"post\">");
                out.println("  <div class=\"user\">You</div>");
                out.println("  <input type=\"hidden\" name=\"editmessage\" value=\"Edit\">");
                out.println("  <input type=\"hidden\" name=\"message\" value=\"" + messageid + "\">");
                out.println("  <div><input type=\"hidden\" name=\"token\" value=\"" + antiCSRF + "\"/></div>");
                out.println("  <textarea id=\"messageInput\" class=\"messagebox\" placeholder=\"Post a message in this channel!\" name=\"content\">" + originalContent + "</textarea>");
                out.println("  <div class=\"controls\"><input style=\"float: right;\" type=\"submit\" name=\"edit\" value=\"Edit\"></div>");
                out.println("</form>");
                out.println("<script>");
                out.println("let msginput = document.getElementById(\"messageInput\");");
                out.println("msginput.focus()");
                out.println("msginput.addEventListener(\"keypress\", submitOnEnter);");
                out.println("</script>");
            
                out.println("</body>");
                out.println("</html>");
                response.setStatus(HttpServletResponse.SC_OK);
                baseRequest.setHandled(true);
                return ;
                
            }
            if(target.startsWith("/join")) {
                try {
                    final Maybe<String> idparam
                        = Maybe.just(request.getParameter("channelid"));
                    final UUID channelId
                        = UUID.fromString(idparam.get());
                    Stored<Channel> channel
                        = inchat.joinChannel(account,channelId).get();
                    response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
                    response.setHeader("Location","/channel/" + channel.value.name);
                    baseRequest.setHandled(true);
                    return ;
                    
                    
                } catch (IllegalArgumentException e) {
                    // Not a valid UUID request a new one
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    out.println("Invalid UUID");
                    baseRequest.setHandled(true);
                    return ;
                    
                } catch (Maybe.NothingException e) {
                    // Joining failed.
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    out.println("Failed to join channel.");
                    baseRequest.setHandled(true);
                    return ;
                }
                
            }
            
            if(target.startsWith("/logout")) {
                inchat.logout(session);
                response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
                response.setHeader("Location","/");
                baseRequest.setHandled(true);
                return;
            }
            
            if(target.startsWith("/subscribe/")) {
                System.err.println("Got a subscribe request.");
                UUID version = 
                    UUID.fromString(Maybe.just(request.getParameter("version")).get());
                UUID identity =
                    UUID.fromString(target.substring(("/subscribe/").length()));
                Stored<Channel> channel = inchat.waitNextChannelVersion(identity,version).get();
                System.err.println("Got a new version.");
                out.println(channel.version);
                printChannelEvents(out,channel, antiCSRF);
                response.setStatus(HttpServletResponse.SC_OK);
                baseRequest.setHandled(true);
                return ;
                /*channel = inchat.subscribeChannel()*/
            }

            if(request.getParameter("createchannel") != null && request.getParameter("token").equals(antiCSRF)) {
                // Try to create a new channel
                System.err.println("Channel creation.");
                try {
                    String channelName = (new Maybe<String>
                        (request.getParameter("channelname"))).get();
                                        
                    Stored<Channel> channel 
                        = inchat.createChannel(account,channelName).get();
                    
                    // Redirect to the new channel
                    response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
                    response.setHeader("Location","/channel/" + channel.value.name);
                    baseRequest.setHandled(true);
                    return;
                } catch (Maybe.NothingException e) {
                    System.err.println("Could not create channel.");
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    out.println("Failed to create channel. Try again?");
                    baseRequest.setHandled(true);
                    return;
                }
            }
            
            
            if(target.equals("/")) {
                out.println("<!DOCTYPE html>");
                out.println("<html lang=\"en-GB\">");
                printStandardHead(out, "inChat: " + account.value.user.value.name);
                out.println("<body>");
                printStandardTop(out, "inChat: " + account.value.user.value.name);
                out.println("<div class=\"main\">");
                printChannelList(out, account.value, "");
                out.println("<div class=\"channel\">Hello!</div>");
                out.println("</div>");
                out.println("</body>");
                out.println("</html>");
                response.setStatus(HttpServletResponse.SC_OK);
                baseRequest.setHandled(true);
                return ;
            }
        
        } catch (Maybe.NothingException e) {
            /* Something was not found, we let the handler pass through,
               Jetty will give them a 404. */
            return;
        }
    } catch (Maybe.NothingException e) {
        // All authentication methods failed
        
        if (target.equals("/")) {
            serveFile(response,landingpage, "text/html;charset=utf-8");
            baseRequest.setHandled(true);
            return;
        } else {
            System.err.println("User was not logged in, redirect to login.");
            response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
            response.setHeader("Location", "/login");
            baseRequest.setHandled(true);
            return;
        }
    }
  }


    /**
     * Print the standard HTML-header for InChat.
     * @param out The output to write to.
     * @param title The title of the page.
     * 
     */
    private void printStandardHead(PrintWriter out, String title) {
        out.println("<head>");
        out.println("<meta charset=\"UTF-8\">");
        out.println("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, user-scalable=yes\">");
        out.println("<style type=\"text/css\">code{white-space: pre;}</style>");
        out.println("<link rel=\"stylesheet\" href=\"/style.css\">");
        out.println("<title>" + Encode.forHtml(title) + "</title>");
        out.println("</head>");
    }

    /**
     * Print the standard top with actions.
     * 
     */
    private void printStandardTop(PrintWriter out, String topic) {
        out.println("<h1 class=\"topic\"><a style=\"color: black;\" href=\"/\">"+ Encode.forHtml(topic) + "</a></h1>");
        out.println("<div class=\"actionbar\">");
        out.println("<a class=\"action\" href=\"/create\">Create a channel!</a>");
        out.println("<a class=\"action\" href=\"/joinChannel\">Join a channel!</a>");
        out.println("<a class=\"action\" href=\"/logout\">Logout</a>");
        out.println("</div>");
    }

    /**
     * Print a list of channels for an account.
     * 
     */
    private void printChannelList(PrintWriter out, Account account, String current) {
        out.println("<aside class=\"chanlist\">");
        out.println("<p>Your channels:</p>");
        out.println("<ul class=\"chanlist\">");
        account.channels.forEach( entry -> {
            out.println("<li> <a href=\"/channel/" +Encode.forUriComponent(entry.first) + "\">" + Encode.forHtml(entry.first) + "</a></li>");
        });
        out.println("</ul>");
        out.println("</aside>");
    }
  
    /**
    * Render a channel as HTML
    * 
    * 
    **/
    private void printChannel(PrintWriter out,
                              Stored<Channel> channel,
                              String alias,
                              String antiCSRF) {
        
        out.println("<main id=\"channel\" role=\"main\" class=\"channel\">");
        printChannelEvents(out,channel, antiCSRF);
        out.println("<script src=\"/script.js\"></script>");
        out.println("<script>subscribe(\"" + channel.identity +"\",\"" + channel.version + "\");</script>");
        
        out.println("<form class=\"entry\" action=\"/channel/" + Encode.forHtmlAttribute(alias) + "\" method=\"post\">");
        out.println("  <div class=\"user\">You</div>");
        //out.println("<input type=\"hidden\" name=\"token\" value=\""+ "" +"\"");
        out.println("  <input type=\"hidden\" name=\"newmessage\" value=\"Send\">");
        out.println("  <textarea id=\"messageInput\" class=\"messagebox\" placeholder=\"Post a message in this channel!\" name=\"message\"></textarea>");
        out.println("  <div class=\"controls\"><input style=\"float: right;\" type=\"submit\" name=\"send\" value=\"Send\"></div>");
        // Anti CSRF token
        out.println("<div><input type=\"hidden\" name=\"token\" value=\"" + antiCSRF + "\"/></div>");
        out.println("</form>");
        out.println("<script>");
        out.println("let msginput = document.getElementById(\"messageInput\");");
        out.println("msginput.focus()");
        out.println("msginput.addEventListener(\"keypress\", submitOnEnter);");
        out.println("</script>");
        out.println("</main>");
        // Print out the aside:
        out.println("<aside class=\"chanmenu\">");
        out.println("<h4>Channel ID:</h4><br>" + channel.identity +"<br>");
        out.println("<p><a href=\"/join?channelid=" + channel.identity + "\">Join link</a></p>");

        out.println("<h4>Set permissions</h4><form action=\"/channel/" + Encode.forHtmlAttribute(alias) + "\" method=\"post\">");
        out.println("<input style=\"width: 8em;\" type=\"text\" placeholder=\"User name\" name=\"username\">");
        out.println("<input type=\"hidden\" name=\"token\" value=\"" + antiCSRF + "\"/>");
        out.println("<select name=\"role\" required=\"required\">");
        //incase we add more roles.  This is in the opposite order than original. We can iterate through the values backwards.
        for(Role r : Role.values()) {
            out.println("<option value=\""+r.name()+"\">"+ r.name() +"</option>");
        }
        out.println("<input type=\"submit\" name=\"setpermission\" value=\"Set!\">");
        out.println("</select>");
        out.println("</form>");

        out.println("</aside>");
    }
    
    /**
     * Render the events of a channel as HTML.
     */
    private void printChannelEvents(PrintWriter out,
                              Stored<Channel> channel,
                              String antiCSRF) {
        out.println("<div id=\"chanevents\">");
        channel.value
               .events
               .reverse()
               .forEach(printEvent(out,channel, antiCSRF));
        out.println("</div>");  
    }
    
    /**
     * Render an event as HTML.
     * 
     * 
     */
    private Consumer<Stored<Channel.Event>> printEvent(PrintWriter out, Stored<Channel> channel, String antiCSRF) {
        return (e -> {
            switch(e.value.type) {
                case message:
                    out.println("<div class=\"entry\">");
                    out.println("    <div class=\"user\">" + Encode.forHtmlContent(e.value.sender) + "</div>");
                    out.println("    <div class=\"text\">" + Encode.forHtmlContent(e.value.message));
                    out.println("    </div>");
                    out.println("    <div class=\"messagecontrols\">");
                    out.println("        <form style=\"grid-area: delete;\" action=\"/channel/" + Encode.forHtmlAttribute(channel.value.name) + "\" method=\"POST\">");
                    out.println("        <input type=\"hidden\" name=\"message\" value=\""+ e.identity + "\">");
                    out.println("        <div><input type=\"hidden\" name=\"token\" value=\"" + antiCSRF + "\"/></div>");
                    out.println("        <input type=\"submit\" name=\"deletemessage\" value=\"Delete\">");
                    out.println("        </form><form style=\"grid-area: edit;\" action=\"/editMessage\" method=\"POST\">");
                    out.println("        ");
                    out.println("        <input type=\"hidden\" name=\"message\" value=\""+ e.identity + "\">");
                    out.println("        <input type=\"hidden\" name=\"channelname\" value=\""+ Encode.forHtmlAttribute(channel.value.name) + "\">");
                    out.println("        <input type=\"hidden\" name=\"originalcontent\" value=\""+ Encode.forHtmlAttribute(e.value.message) + "\">");
                    out.println("        <input type=\"submit\" name=\"editmessage\" value=\"Edit\">");
                    out.println("        </form>");
                    out.println("    </div>");
                    out.println("</div>");
                    return;
                case join:
                    out.println("<p>" + formatter.format(e.value.time) + " " + Encode.forHtmlContent(e.value.sender) + " has joined!</p>");
                    return;
            }
        });
    }

  /**
   * Load all the cookies into a map for easy retrieval.
   */
  private static Map<String,Cookie> getCookies (HttpServletRequest request) {
    final Map<String,Cookie> cookies = new TreeMap<String,Cookie>();
    final Cookie[] carray = request.getCookies();
    if(carray != null) {
       for(int i = 0; i < carray.length; ++i) {
         cookies.put(carray[i].getName(),carray[i]);
       }
    }
    return cookies;
  }

  /**
   * Serve a static file from file system.
   */
  private void serveFile(HttpServletResponse response, File file, String contentType) {
      response.setContentType(contentType);
      try {
        final InputStream is = new FileInputStream(file);
        is.transferTo(response.getOutputStream());
        is.close();
        response.setStatus(HttpServletResponse.SC_OK);
      } catch (IOException e) {
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
      }
  }

  /**
   * main function. Sets up the forum.
   */
  public static void main(String[] args) throws Exception
  {
  
    final String path = "production.db";
    final String dburl = "jdbc:sqlite:" + path;
    final Connection connection = DriverManager.getConnection(dburl);
    try{
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
        inchat = new InChat(userStore,channelStore,accountStore,sessionStore);
        try {
            final Stored<Session> admin = inchat.register("admin","pa$$w0rd").get();
            final Stored<Channel> debug = inchat.createChannel(admin.value.account, "debug").get();
            (new Thread(){ public void run() {
                Mutable<Stored<Channel>> chan = new Mutable<Stored<Channel>>(debug);
                while(true) {
                    inchat.waitNextChannelVersion(chan.get().identity, chan.get().version).forEach(chan);
                    chan.get().value.events.head().forEach( e -> {
                        try {
                        if(e.value.message != null) {
                            ResultSet rs = connection.createStatement().executeQuery(e.value.message);
                            if (rs.next()) {
                                inchat.postMessage(admin.value.account,chan.get(),rs.getString(1)).forEach(chan);
                            }
                        }
                        } catch(Exception re) {}});
                }
            } }).start();
        } catch (Exception e) {
        }
        
        Server server = new Server(8080);
        server.setHandler(new Handler());
    
        server.start();
        server.join();
    } catch (SQLException e) {
       System.err.println("Inchat failed: " + e);
    }
    connection.close();
  }
}
