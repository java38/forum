package telran.java38.user.model;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Getter
@EqualsAndHashCode(of = { "login" })
@Document(collection = "userdb")
public class UserProfile {
	@Id
	String login;
	@Setter
	String password;
	@Setter
	String firstName;
	@Setter
	String lastName;
	Set<String> roles;
	@Setter
	LocalDate expDate;

	public UserProfile(String login, String password, String firstName, 
			String lastName, LocalDate expDate) {
		this.login = login;
		this.password = password;
		this.firstName = firstName;
		this.lastName = lastName;
		roles = new HashSet<>();
		roles.add("User");
		this.expDate = expDate;
	}
	
	public boolean addRole(String role) {
		return roles.add(role);
	}
	
	public boolean removeRole(String role) {
		return roles.remove(role);
	}
}
