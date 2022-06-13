package com.example.springoauth2demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@SpringBootApplication
@RestController
public class SpringOauth2DemoApplication extends WebSecurityConfigurerAdapter {

	private final Logger log = LoggerFactory.getLogger(SpringOauth2DemoApplication.class);

	@GetMapping("/user")
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
		String name = principal.getAttribute("login");
		log.info("principal {}", name);
		return Collections.singletonMap("name", name);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests(a -> a
						.antMatchers("/", "/error", "webjars/**").permitAll()
						.anyRequest().authenticated()
				)
				.exceptionHandling(e -> e
						.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
				)
				.csrf(c -> c
						.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
				.logout(l -> l
						.logoutSuccessUrl("/").permitAll())
				.oauth2Login();
	}

	@GetMapping("favicon.ico")
	@ResponseBody
	public void returnNoFavicon() {
	}

	public static void main(String[] args) {
		SpringApplication.run(SpringOauth2DemoApplication.class, args);
	}

}
