package app.oauth.security.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import app.oauth.services.IUserService;
import app.userscommons.models.entity.User;
import brave.Tracer;
import feign.FeignException;

@Component
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {

	@Autowired
	IUserService userService;
	
	@Autowired
	private Tracer tracer;
	

	private Logger log = LoggerFactory.getLogger(AuthenticationSuccessErrorHandler.class);

	@Override
	public void publishAuthenticationSuccess(Authentication authentication) {
		UserDetails user = (UserDetails) authentication.getPrincipal();
		log.info("Success Login: " + user.getUsername());
		User userSer = userService.findByUsername(authentication.getName());
		if (userSer.getAttempts() != null && userSer.getAttempts() > 0) {
			userSer.setAttempts(0);
			userService.update(userSer, userSer.getId());
		}
	}

	@Override
	public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		String message = "Error Login: " + exception.getMessage();
		log.error(message);

		try {
			StringBuilder errors = new StringBuilder();
			errors.append(message);
			User user = userService.findByUsername(authentication.getName());
			if (user.getAttempts() == null) {
				user.setAttempts(0);
			}
			log.info("Current attempts are " + user.getAttempts());
	
			user.setAttempts(user.getAttempts() + 1);
	
			log.info("Attempts after are " + user.getAttempts());
			errors.append(" - Login attempts: " + user.getAttempts());
			
			if (user.getAttempts() >= 3) {
				String errorMaxAtt = String.format("User %s disabled exceed maximum attemps.", authentication.getName());
				log.error(errorMaxAtt);
				errors.append(" - " + errorMaxAtt);
				user.setEnabled(false);
			}
	
			userService.update(user, user.getId());
			
			tracer.currentSpan().tag("error.message", errors.toString());
		} catch (FeignException e) {
			log.error(String.format("User %s doesn't exists", authentication.getName()));
		}

	}

}
