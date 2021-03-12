package inf226.inchat;

import com.lambdaworks.crypto.SCryptUtil;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public final class Password {
	private final String key;
	private static final int N = 16384;
	private static final int r = 8;
	private static final int p = 1;

    private static final int MINIMUM_LENGTH = 8;
    private static final int MAXIMUM_LENGTH = 64;

	public Password(String key) {

		this.key = key;
	}

	/**
	 * @param password
	 * @return a new Password with the KDF-value of the given password.
	 *
	 *TODO: Should probably use validPassword so every new password follows NIST Password requirements
	 */
	public static Password createPassword(String password) {
		String key = SCryptUtil.scrypt(password, N, r, p);
		return new Password(key);
	}

	public boolean check(String password) {
		if(password.isEmpty()) return false;
		return SCryptUtil.check(password, this.key);
	}


    /**
     * @param password
     * @return true if given password follows the NIST password guidelines
     */
    public static boolean validPassword(String password) {
        int length = password.length();
        return length >= MINIMUM_LENGTH
                && length <= MAXIMUM_LENGTH
                && !inDictionary(password)
                && !sequential(password)
                && !repeating(password)
                && !leaked(password);
    }

	// Checks for sequences in password
	public static boolean sequential(String password) {

		// List of dissallowed sequences
		ArrayList<String> sequentials = new ArrayList<>(Arrays.asList("abc", "bcd", "cde", "def", "efg", "fgh", "ghi",
                "hij", "ijk", "jkl", "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst", "stu", "tuv", "uvw", "vwx",
                "wxy", "xyz", "012", "123", "234", "345", "456", "567", "678", "789"));
        for (int i = 0; i < sequentials.size(); i++) {
            if (password.contains(sequentials.get(i))) {
                return true;
            }
        }

        return false;
	}

	// Checks for repeating characters in password, only allowed 2 repeating chars
	public static boolean repeating(String password) {
		int n = 0;
        for (int i = 0; i < password.length() - 1; i++) {
            if (password.charAt(i) == password.charAt(i + 1)) {
                n++;
            } else {
                n = 0;
            }
            if (n == 2) {
                return true;
            }
		}

		return false;
	}

	public static boolean inDictionary(String password) {
		final String file = "dictionary.txt";
		String line = null;
		ArrayList<String> words = new ArrayList<>();

		try {
			FileReader reader = new FileReader(file);
			BufferedReader fileBuff = new BufferedReader(reader);
			while((line = fileBuff.readLine()) != null) {
				words.add(line);
			}
			fileBuff.close();
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

		for(String word : words) {
			if (password.contains(word)) {
				return true; // Word was found inside password
			}
		}
		return false;
	}

	// Checks to see if password can be found in a large database of leaked passwords
	public static boolean leaked(String password) {
		final String file = "badPasswords.txt";
		String line = null;
		ArrayList<String> badPasswords = new ArrayList<>();

		try {
			FileReader reader = new FileReader(file);
			BufferedReader fileBuff = new BufferedReader(reader);
			while ((line = fileBuff.readLine()) != null) {
				badPasswords.add(line);
			}
			fileBuff.close();
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		return badPasswords.contains(password);
	}

	@Override
	public String toString() {
		return key;
	}

}
