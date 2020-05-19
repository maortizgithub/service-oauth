package app.oauth.services;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import app.oauth.clients.UserFeignClient;
import brave.Tracer;
import feign.FeignException;

@Service
public class UserService implements IUserService, UserDetailsService {

	private Logger log = LoggerFactory.getLogger(UserService.class);

	@Autowired
	private UserFeignClient client;
	
	@Autowired
	private Tracer tracer;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		try {

			app.userscommons.models.entity.User user = client.findByUsername(username);

			List<GrantedAuthority> authorities = user.getRoles().stream()
					.map(role -> new SimpleGrantedAuthority(role.getName()))
					.peek(authority -> log.info("Role: " + authority.getAuthority())).collect(Collectors.toList());

			log.info("Autenthicated user : " + username);

			return new User(user.getUsername(), user.getPassword(), user.getEnabled(), true, true, true, authorities);
		} catch (FeignException e) {
			String error = "Login Error, user '" + username + "' doesn't exists";
			log.error(error);
			tracer.currentSpan().tag("error.message", error +": " + e.getMessage());
			throw new UsernameNotFoundException(error);
		}
	}

	@Override
	public app.userscommons.models.entity.User findByUsername(String username) {
		return client.findByUsername(username);
	}

	@Override
	public app.userscommons.models.entity.User update(app.userscommons.models.entity.User user, Long id) {
		return client.update(user, id);
	}

}
