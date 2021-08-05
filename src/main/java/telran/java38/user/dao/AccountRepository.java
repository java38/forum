package telran.java38.user.dao;

import org.springframework.data.mongodb.repository.MongoRepository;

import telran.java38.user.model.UserProfile;

public interface AccountRepository extends MongoRepository<UserProfile, String> {

}
