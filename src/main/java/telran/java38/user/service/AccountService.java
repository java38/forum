package telran.java38.user.service;

import java.util.Set;

import telran.java38.user.dto.UserProfileDto;
import telran.java38.user.dto.UserRegDto;
import telran.java38.user.dto.UserUpdateDto;

public interface AccountService {
	UserProfileDto addUser(UserRegDto userRegDto);

	UserProfileDto findUserById(String login);
	
	UserProfileDto updateUser(String login, UserUpdateDto userUpdateDto);
	
	UserProfileDto removeUser(String login);
	
	void changePassword(String login, String password);
	
	Set<String> updateRolesList(String login, String role, boolean isSet);
	
	

}
