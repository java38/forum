package telran.java38.user.dto.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.CONFLICT)
public class UserConflictException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 7730290583073992140L;
	
	public UserConflictException(String login) {
		super("User " + login + " is exists");
	}

}
