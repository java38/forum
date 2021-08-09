package telran.java38.user.controller;

import java.security.Principal;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import telran.java38.user.dto.UserPasswordDto;
import telran.java38.user.dto.UserProfileDto;
import telran.java38.user.dto.UserRegDto;
import telran.java38.user.dto.UserRoleDto;
import telran.java38.user.dto.UserUpdateDto;
import telran.java38.user.service.AccountService;

@RestController
@RequestMapping("/account")
public class AccountManagmentController {

	AccountService accountService;

	@Autowired
	public AccountManagmentController(AccountService accountService) {
		this.accountService = accountService;
	}

	@PostMapping
	public UserProfileDto register(@RequestBody UserRegDto userRegDto) {
		return accountService.addUser(userRegDto);
	}

	@PostMapping("/login")
	public UserProfileDto userLogin(Principal principal) {
		return accountService.findUserById(principal.getName());
	}

	@PutMapping("/{login}")
	public UserProfileDto updateUser(@PathVariable String login, @RequestBody UserUpdateDto userUpdateDto) {
		return accountService.updateUser(login, userUpdateDto);
	}

	@DeleteMapping("/{login}")
	public UserProfileDto removeUser(@PathVariable String login) {
		return accountService.removeUser(login);
	}

	@PutMapping("/{login}/password")
	public void updateUser(@PathVariable String login, @RequestBody UserPasswordDto userPasswordDto) {
		accountService.changePassword(login, userPasswordDto.getPassword());
	}

	@PutMapping("/{login}/role")
	public Set<String> updateUserRole(@PathVariable String login, @RequestBody UserRoleDto userRoleDto) {
		return accountService.updateRolesList(login, userRoleDto.getRole(), userRoleDto.isAddRole());
	}

}
