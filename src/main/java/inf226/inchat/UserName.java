package inf226.inchat;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


public final class UserName {
	private static final int MINIMUM_LENGTH = 4;
	private static final int MAXIMUM_LENGTH = 40;
	private static final String VALID_CHARACTERS = "[A-Za-z0-9_-]+";

	private final String Username;
	
	public UserName(String Username) {
		this.Username = Username;
	}

	public static boolean validUsername(String username){
		int length = username.length();
		Pattern pattern = Pattern.compile(VALID_CHARACTERS);
		Matcher matcher = pattern.matcher(username);

		return matcher.find()
				&& length >= MINIMUM_LENGTH
				&& length <= MAXIMUM_LENGTH;
	}

	@Override
	public String toString() {
		return this.Username;
	}
}
