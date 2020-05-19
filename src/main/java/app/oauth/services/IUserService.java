package app.oauth.services;

import app.userscommons.models.entity.User;

public interface IUserService {

	public User findByUsername(String username);
	
	public User update(User user, Long id);

}
