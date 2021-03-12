# INCHAT – The INsecure CHAT application

Welcome to this second mandatory assignment of INF226.
In this assignment you will be improving the security
of a program called inChat – a very simple chat application,
in the shape of a [Jetty](https://www.eclipse.org/jetty/)
web application.

inChat has been especially crafted to contain a number
of security flaws. You can imagine that it has been
programmed by a less competent collegue, and that after
numerous securiy incidents, your organisation has decided
that you – a competent security professional – should take
some time to secure the app.

For your convenience, the task is separated into specific
exercises or tasks. These task might have been the result
of a security analysis. If you discover any security issues
beyond these tasks, you can make a note of them at the
end of this report.

For each task, you should make a short note how you solved
it – ideally with a reference to the relevant git-commits you
have made.

## Evaluation

This assignment is mandatory for the course, and counts 20%
of your final grade. The assigment is graded 0–20 points,
where you must get a minimum of 6 points in order to pass
the assignment.

## Groups

As with the previous assignments, you can work in groups of 1–3 students
on this assginment. Make sure that everyone is signed up for the group
on [MittUiB](https://mitt.uib.no/courses/24957/groups#tab-8746).
One good way to collaborate is that one person on the group makes a
fork and adds the other group members to that project.

## Getting and building the project

Log into [`git.app.uib.no`](https://git.app.uib.no/Hakon.Gylterud/inf226-2020-inchat) and make your
own fork of the project there. *Make sure your fork is private!*
You can then clone your repo to your own persion machine.

To build the project you can use Maven on the command line, or configure
your IDE to use Maven to build the project.

 - `mvn compile` builds the project
 - `mvn test` runs the tests. (There are only a few unit test – feel free to add more).
 - `mvn exec:java` runs the web app.

Once the web-app is running, you can access it on [`localhost:8080`](http://localhost:8080/).

## Handing in the assignment

Before you hand in your assignment, make sure that you
have included all dependencies in the file `pom.xml`, and
that your program compiles and runs well. One good way
to test this is to make a fresh clone from the GitLab repo,
compile and test the app.

Once you are done, you submit the assignment on
[`mitt.uib.no`](https://mitt.uib.no/) as a link to your
fork – one link per group. This means you should not commit to the
repository after the deadline has passed. Include the commit hash
of the final commit (which you can find `git log`, for instance) in
your submission on MittUiB.

Remember to make your fork accessible to the TAs and lecturer. You can do
this from GitLab's menu, "Settings" → "Members".
Add the following people as developers:

 - Alba Gullerud,
 - Kenneth Fossen,
 - Jonas Møller,
 - Erlend Nærbø ,
 - Benjamin Chetioui, and
 - Håkon Gylterud

## Updates

Most likely the source code of the project will be updated by Håkon
while you are working on it. Therefore, it will be part of
your assignment to merge any new commits into your own branch.

## Improvements?

Have you found a non-security related bug?
Feel free to open an issue on the project GitLab page.
The best way is to make a separate `git branch` for these
changes, which do not contain your sulutions.

(This is ofcourse completely volountary – and not a graded
part of the assignment)

If you want to add your own features to the chat app - feel free
to do so! If you want to share them, contact Håkon and we can
incorporate them into the main repo.

## Tasks

The tasks below has been separated out, and marked with their *approximate* weight. Each task has a section called "Notes" where you can
write notes on how you have solved the task.

### Task 0 – Authentication (4 points)

The original authentication mechanisms of inChat was so insecure it
had to be removed immediately and all traces of the old passwords
have been purged from the database. Therefore, the code in
`inf226.inchat.Account`, which is supposed to check the password,
always returns `true`.

#### Task 0 – Part A

*Update the code to use a secure password authentication method – one
of the methods we have discussed in lecture.*

Any data you need to store for the password check can be kept in the `Account` class, with
appropriate updates to `storage.AccountStorage`. Remember that the `Account` class is *immutable*.
Any new field must be immutable and `final` as well.

**Hint**:

 - An implementation of `scrypt` is already included as a dependency in `pom.xml`.
   If you prefer to use `argon2`, make sure to include it as well.


### Task 0 – Part B

Create two new, immutable, classes `UserName` and `Password` in the
inf226.inchat package, and replace `String` with these
classes in User and Account classes and other places in
the application where it makes sense.

Decide on a set of password criteria which satisfies
the NIST requirements, and implement these as invariants
in the Password class, and check these upon registration.

### Task 0 – Part C

*While the session cookie is an unguessable UUID, you must set the
correct protection flags on the session cookie.*

#### Notes – task 0

Here you write your notes about how this task was performed.

##### Part A

We use SCrypt, with the recommended parameters of N = 16384, r = 8, p = 1

##### Part B
The `Password` class checks the nist requirements
`validPasword` 	checks length >= 8, and <= 64
`leaked`	screens the passwords against known leaked passwords
The `LoginHandler` class tracks failed login attempts and locks an account for 10 minutes after 10 failed login attempts

The `Password` class also checks for weak passwords, only allowing passwords that pass these checks.
`inDictionary` 	checks weather the password is in the dictionary,
`sequential` 	checks for sequences in the password
`repeating`	checks for repeating characters in the password, only allowing 2 repeating characters.


##### Part C

We made a new Password class that contains a KDF-derived hash of the password given. We are using SCRYPT for this one-way encryption.

In the code given we used the Cookie class and used the given methods:

- setSecure(true)
- setHttpOnly(true)
But since the version we are using do not have a samesite attribute, we used setHeader/addHeader to add the cookie instead:
```
response.setHeader("Set-Cookie", "session =" + session.identity.toString() + "; HttpOnly; SameSite=strict");
```
If we wanted to add the secure property we could add ; Secure, at the end of the string.




### Task 1 – SQL injection (4 points)

The SQL code is currently wildly concatenating strings, leaving
it wide open to injection attacks.

*Take measures to prevent SQL injection attacks on the application.*

#### Notes – task 1

Here you write your notes about how this task was performed.

We changed the unsafe SQL-statements into prepared statements.

### Task 2 – Cross-site scripting (4 points)

The user interface is generated in `inf226.inchat.Handler`. The current
implementation is returning a lot of user data without properly
escaping it for the context it is displayed (for instance HTML body).

*Take measures to prevent XSS attacks on inChat.*

**Hint**: In addition to the books and the lecture slides, you should
take a look at the [OWASP XSS prevention cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

#### Notes – task 2

Here you write your notes about how this task was performed.

By using a HttpOnly cookie, and encoding every untrusted input we will stop most xxs-related attacks.
We did this by:
- Having HttpOnly set true in the session cookie.
- Using OWASP Java Encoder to encode all untrusted data in Handler.java



### Task 3 – Cross-site request forgery (1 point)

While the code uses UUIDs to identify most objects, some
form actions are still susceptible to cross-site request forgery attacks
(for instance the `newmessage` and the `createchannel` actions.)

*Implement anti-CSRF tokens or otherwise prevent CSRF on
the vulnerable forms.*

**Hint:** it is OK to use the session cookie as such a token.

#### Notes – task 3

Here you write your notes about how this task was performed.

We did this by adding a CSRF token (in our case the session-token as the assignment said it was OK, although that is not advised by OWASP) on every form in the handler, and checked if the request contained the token value that corresponded to the token value produced by the program.

We also use the samesite property in the session cookie, which also helps against CSRF, but only on newer browsers.


### Task 4 – Access control (5 points)

inChat has no working access control. The channel side-bar has a form
to set roles for the channel,
but the actual functionality is not implemented.

In this task you should implement access control for inChat.

 - Identify which actions need access control, and decide
   on how you want to structure the access control.

Connect the user interface in the channel side-bar to your
access control system so that the security roles work as
intended. The security roles in a channel are:

 - *Owner*: Can set roles, delete and edit any message, as
   well as read and post to the channel.
 - *Moderator*: Can delete and edit any message, as
   well as read and post to the channel.
 - *Participant*: Can delete and edit their own messages, as
   well as read and post to the channel.
 - *Observer*: Can read messages in the channel.
 - *Banned*: Has no access to the channel.

The default behaviour should be that the creator of the
channel becomes the owner, and that inviting someone
puts them at the "Participant" level.
Also, make sure that your system satisfies the invariant:

 - Every channel has at least one owner.

 **Hint:** The InChat class is best suited to implement the
 access control checks since it in charge of all the operations
 on the chat. Implement a "setRole" method there, and add
 security checks to all other methods.

#### Notes – task 4

Here you write your notes about how this task was performed.

To avoid duplicate data we added a role to the AccountChannels data.
We made a ENUM with the different roles from: Banned to Owner.
Every method that requires some kind of permission in inChat.java checks if the user calling that method is allowed to do so.

TODO: Need to ensure that every channel has at least one owner!


### Task ω – Other security holes (2 points)

There are more security issues in this web application.
Improve the security of the application to the best of your
ability.

A note about HTTPS: We assume that inChat will be running
behind a reverse proxy which takes care of HTTPS, so you
can ignore issues related HTTPS.


#### Notes – task ω

Here you write your notes about how this task was performed.

TODO: As the program is now, we have cases of duplicate users / channels which will "confuse" certain methods where the names/aliases of these objects are used as keys. (lookup etc)

Using version 9.4.32.v20200930 of Jetty. As version 9.4.9 20180320 has these vulnerabilities:
- CVE-2019-10247
- CVE-2019-10241
- CVE-2018-12545
- CVE-2018-12536
- CVE-2017-7658
- CVE-2017-7657
- CVE-2017-7656

We set a CSP that will mitigate some XSS and data injection attacks:  
```
response.addHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'none';")
```
