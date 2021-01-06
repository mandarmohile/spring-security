package me.amigoscode.springboothelper.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import me.amigoscode.springboothelper.auth.ApplicationUserService;
import me.amigoscode.springboothelper.jwt.JwtConfig;
import me.amigoscode.springboothelper.jwt.JwtTokenVerifierFilter;
import me.amigoscode.springboothelper.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import static me.amigoscode.springboothelper.security.ApplicationUserRole.*;

import javax.crypto.SecretKey;

import static me.amigoscode.springboothelper.security.ApplicationUserPermission.*;

/*
 * https://www.baeldung.com/spring-boot-security-autoconfiguration
 * 
 * @EnableWebSecurity
 *  This annotation turns off the default spring web application security 
 *  but leaves the authentication manager (Actuator security) available.
 *  The same can also be turned-off/configured by over-riding WebSecurityConfigurerAdapter.java's configure method
 *  	 viz. configure(AuthenticationManagerBuilder auth)
 *  by instructing how authentication can be performed.
 *  Basically, its use is to turn-off default spring web application security with custom configuration.
 *
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

	/**
	// The following code is required during Basic and Form Authentication.
	// It has been commented for JWT implementation.

	private final PasswordEncoder passwordEncoder;

	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		/*
		 * Below line of code is necessary when using HTTP methods 
		 * like POST, PUT or DELETE else Forbidden Error is thrown.
		 * Should always be included when client is non-browser.
		 *
		//.csrf().disable() 
		.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
		.authorizeRequests()
		/*
		 * please note that "/index.html" should be written instead of "index"
		 *
		.antMatchers("/", "/index.html", "/css/*", "/js/*").permitAll()
		.antMatchers("/api/student-controller/**").hasRole(STUDENT.name()) // role based access to resources (where resources are API)
//      .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//      .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//      .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
		.anyRequest().authenticated()
		.and()
		.httpBasic();
	}

	// Hard-coding user ROLES for login.
	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails annaSmithUser = User.builder().username("annasmith").password(passwordEncoder.encode("password"))
				//.roles(STUDENT.name()) // ROLE_STUDENT (this is how Spring shall treat roles internally).
				.authorities(STUDENT.getGrantedAuthorities())
				.build();

		UserDetails lindaUser = User.builder().username("linda").password(passwordEncoder.encode("password"))
				//.roles(ADMIN.name()) // ROLE_ADMIN
				.authorities(ADMIN.getGrantedAuthorities())
				.build();

		UserDetails tomUser = User.builder().username("tom").password(passwordEncoder.encode("password"))
				//.roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
				.authorities(ADMINTRAINEE.getGrantedAuthorities())
				.build();

		return new InMemoryUserDetailsManager(annaSmithUser, lindaUser, tomUser);

	}
	**/
	
	private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService,
                                     SecretKey secretKey,
                                     JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }
	
	@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifierFilter(secretKey, jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

}
