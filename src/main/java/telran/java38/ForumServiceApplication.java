package telran.java38;

import java.time.LocalDate;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import telran.java38.user.dao.AccountRepository;
import telran.java38.user.model.UserProfile;

@SpringBootApplication
public class ForumServiceApplication implements CommandLineRunner{
	
	@Autowired
	AccountRepository accountRepository;

	public static void main(String[] args) {
		SpringApplication.run(ForumServiceApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		if(!accountRepository.existsById("admin")) {
			String hashPassword = BCrypt.hashpw("admin", BCrypt.gensalt());
			UserProfile admin = new UserProfile("admin", hashPassword, "", "");
			admin.addRole("Moderator");
			admin.addRole("Administrator");
			admin.setExpDate(LocalDate.now().plusYears(25));
			accountRepository.save(admin);
		}
		
	}

}
