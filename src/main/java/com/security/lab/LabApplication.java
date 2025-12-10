package com.security.lab;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import jakarta.annotation.PostConstruct;

@SpringBootApplication
@RestController
public class LabApplication {

	@Autowired JdbcTemplate db;

	public static void main(String[] args) { SpringApplication.run(LabApplication.class, args); }

	@PostConstruct
	public void init() {
		// Create table and insert a dummy admin
		db.execute("CREATE TABLE IF NOT EXISTS users (name TEXT, pass TEXT)");
		db.execute("INSERT INTO users (name, pass) VALUES ('admin', 'secret123')");
	}

	// Force response to be HTML so the browser executes the script
	@PostMapping(value = "/register", produces = "text/html")
	public String register(String user, String pass) {
		// VULNERABLE: Direct SQL concatenation
		String sql = "INSERT INTO users VALUES ('" + user + "', '" + pass + "')";
		db.execute(sql);
		return "<h1>Registered: " + user + "</h1><br><a href='/'>Go Back</a>";
	}

	@PostMapping(value = "/login", produces = "text/html")
	public String login(String user, String pass) {
		// VULNERABLE: Direct SQL concatenation
		String sql = "SELECT count(*) FROM users WHERE name = '" + user + "' AND pass = '" + pass + "'";
		try {
			int count = db.queryForObject(sql, Integer.class);
			if (count > 0) {
				return "<h1>Welcome " + user + "</h1>";
			} else {
				return "Login Failed";
			}
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}
}