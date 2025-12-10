

package com.security.lab;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;
import jakarta.annotation.PostConstruct;
import java.util.regex.Pattern;

@SpringBootApplication
@RestController
public class LabApplication {

	@Autowired JdbcTemplate db;

	// Professional Password Hasher
	private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

	// Password Policy: Min 8 chars, at least 1 letter and 1 number
	private final Pattern strongPassParams = Pattern.compile("^(?=.*[A-Za-z])(?=.*\\d).{8,}$");

	public static void main(String[] args) { SpringApplication.run(LabApplication.class, args); }

	@PostConstruct
	public void init() {
		db.execute("CREATE TABLE IF NOT EXISTS users (name TEXT, pass TEXT)");
	}

	@PostMapping(value = "/register", produces = "text/html")
	public String register(String user, String pass) {
		// FIX 1: Validate Password Strength
		if (!strongPassParams.matcher(pass).matches()) {
			return "<h3>Error: Password is too weak.</h3>" +
					"<p>Must be at least 8 characters with letters and numbers.</p>" +
					"<a href='/'>Try Again</a>";
		}

		// FIX 2: Check if user already exists (Prevent duplicates)
		String checkSql = "SELECT count(*) FROM users WHERE name = ?";
		int count = db.queryForObject(checkSql, Integer.class, user);
		if (count > 0) return "User already exists!";

		// FIX 3: Hash the password (e.g., turns 'password123' into '$2a$10$wI...')
		String hashedPass = encoder.encode(pass);

		// FIX 4: Secure Insert (Parameterized)
		String sql = "INSERT INTO users (name, pass) VALUES (?, ?)";
		db.update(sql, user, hashedPass);

		// FIX 5: Prevent XSS on output
		return "<h1>Registered: " + HtmlUtils.htmlEscape(user) + "</h1><br><a href='/'>Login</a>";
	}

	@PostMapping(value = "/login", produces = "text/html")
	public String login(String user, String pass) {
		// FIX 6: Secure Retrieval
		// We NEVER select by password. We select by username, then check the hash in Java.
		String sql = "SELECT pass FROM users WHERE name = ?";

		try {
			// Get the stored hash from the database
			String storedHash = db.queryForObject(sql, String.class, user);

			// Compare the input password with the stored hash
			if (encoder.matches(pass, storedHash)) {
				return "<h1>Welcome Back, " + HtmlUtils.htmlEscape(user) + "!</h1>";
			} else {
				return "<h3>Login Failed: Wrong Password</h3><a href='/'>Try Again</a>";
			}
		} catch (EmptyResultDataAccessException e) {
			return "<h3>Login Failed: User not found</h3><a href='/'>Try Again</a>";
		}
	}

	// Add this anywhere inside your Class
	@GetMapping("/show-data")
	public String showData() {
		// 1. Get all rows
		java.util.List<java.util.Map<String, Object>> rows = db.queryForList("SELECT * FROM users");

		// 2. Build a simple HTML string
		StringBuilder output = new StringBuilder("<h1>Database Content</h1><table border='1'><tr><th>User</th><th>Hashed Password</th></tr>");

		for (java.util.Map<String, Object> row : rows) {
			output.append("<tr>");
			output.append("<td>").append(row.get("name")).append("</td>");
			output.append("<td>").append(row.get("pass")).append("</td>");
			output.append("</tr>");
		}

		output.append("</table><br><a href='/'>Back</a>");
		return output.toString();
	}
}