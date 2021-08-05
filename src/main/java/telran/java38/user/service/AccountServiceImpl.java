package telran.java38.user.service;

import java.util.Set;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import telran.java38.user.dao.AccountRepository;
import telran.java38.user.dto.UserProfileDto;
import telran.java38.user.dto.UserRegDto;
import telran.java38.user.dto.UserUpdateDto;
import telran.java38.user.dto.exceptions.UserConflictException;
import telran.java38.user.dto.exceptions.UserNotFoundException;
import telran.java38.user.model.UserProfile;

@Service
public class AccountServiceImpl implements AccountService {

	AccountRepository accountRepository;
	ModelMapper modelMapper;

	@Autowired
	public AccountServiceImpl(AccountRepository accountRepository, ModelMapper modelMapper) {
		this.accountRepository = accountRepository;
		this.modelMapper = modelMapper;
	}

	@Override
	public UserProfileDto addUser(UserRegDto userRegDto) {
		if (accountRepository.existsById(userRegDto.getLogin())) {
			throw new UserConflictException(userRegDto.getLogin());
		}
		UserProfile userProfile = new UserProfile(userRegDto.getLogin(),
				userRegDto.getPassword(), userRegDto.getFirstName(),
				userRegDto.getLastName());
		accountRepository.save(userProfile);
		return modelMapper.map(userProfile, UserProfileDto.class);
	}

	@Override
	public UserProfileDto findUserById(String login) {
		UserProfile userProfile = accountRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));
		return modelMapper.map(userProfile, UserProfileDto.class);
	}

	@Override
	public UserProfileDto updateUser(String login, UserUpdateDto userUpdateDto) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public UserProfileDto removeUser(String login) {
		UserProfile userProfile = accountRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));
		accountRepository.delete(userProfile);
		return modelMapper.map(userProfile, UserProfileDto.class);
	}

	@Override
	public void changePassword(String login, String password) {
		// TODO Auto-generated method stub

	}

	@Override
	public Set<String> updateRolesList(String login, String role, boolean isSet) {
		// TODO Auto-generated method stub
		return null;
	}

}
