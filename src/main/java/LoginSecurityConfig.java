import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class LoginSecurityConfig extends WebSecurityConfigurerAdapter {
	//https://www.journaldev.com/8748/spring-security-role-based-access-authorization-example
//	in configureGlobal() method, we have added two users: One user with “ROLE_USER” role and another user with both “ROLE_USER” and “ROLE_ADMIN” roles. That means this second user will act as a Admin User. Like this we can configure any number of users and roles.
//	We can use either authorities(ROLE) or roles(ROLE) methods to configure Roles in our application.
//	Difference between authorities() and roles() methods:
	// authorities() needs complete role name like “ROLE_USER”
	// roles() needs role name like “USER”. It will automatically adds “ROLE_” value to this “USER” role name.
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder authenticationMgr) throws Exception {
		authenticationMgr.inMemoryAuthentication().withUser("jduser").password("jdu@123").authorities("ROLE_USER").and()
				.withUser("jdadmin").password("jda@123").authorities("ROLE_USER", "ROLE_ADMIN");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests().antMatchers("/homePage").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/userPage").access("hasRole('ROLE_USER')").antMatchers("/adminPage")
				.access("hasRole('ROLE_ADMIN')").and().formLogin().loginPage("/loginPage")
				.defaultSuccessUrl("/homePage").failureUrl("/loginPage?error").usernameParameter("username")
				.passwordParameter("password").and().logout().logoutSuccessUrl("/loginPage?logout");

	}
}