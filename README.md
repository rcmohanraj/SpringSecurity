## Spring Security Features:

1) Created Simple Bootstrap service with StudentController (commit: Bootstrap Project)  
**Service URL:** 
http://localhost:8080/api/v1/students/1

2) Adding Spring Security Dependency to the project (v 2.3.2)
```
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

After restarting the application we can see the hashed password in the console. When we access the URL of retrieving a Student 
we will redirected to http://localhost:8080/login where we will be asking Username and Password (Form based authentication provided by Spring Security).  
Username is user / Password is generated hash in the console.

We can use the below URL to logout as well http://localhost:8080/logout

**BasicAuth:** (Moving from FormBasedAuth to BasicAuth)  
We have to pass Username and Password as Base64 encoded values in Get request headers for each single request. This type of authentication will be 
applicable when calling the external API and this will not be applicable for Form Based Authentication. 

We need to extend WebSecurityConfigurerAdapter class in the ApplicationSecurityConfig, which will have bunch of override methods (to view it control + o).
We can override configure method which accept HttpSecurity as parameter.  

```
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
			.authorizeRequests()//Authorize Request
			.anyRequest()  //All the Request +
			.authenticated() // + Must be authenticated
			.and()
			.httpBasic(); //Using Basic Auth Mechanism
}
```
 
If we hit the Student Service we will get the popup to enter Username and Password

**Points to note in BasicAuth:**  
HTTPS is recommended
Simple and fast
We don't have logout functionality.

We can add the index.html under resource/static, this will show when we hit URL localhost:8080 instead of showing Whitelabel page

**AntMatchers:** (Whitelist some URL)  
We can Whitelist any specific URL using antMatchers. For example we can Whitelist css, js, root, index.html.

```
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
			.authorizeRequests()//Authorize Request
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll() // with specific URL patterns to allow without authentication
			.anyRequest()  //All the Request
			.authenticated() // Must be authenticated
			.and()
			.httpBasic(); //Using Basic Auth Mechanism
}
```

**User Roles:**  
Role is a high level view of all the users that we have in the system. More than one role can be assigned to user.

We need to override the method userDetailsService from WebSecurityConfigurerAdapter class in ApplicationSecurityConfig. In this method we can do db fetch to get the
user details. We can use the User.builder to build the user details. Also the password must be encoded, so we need to implement anyone 
of the password encoder implementation for PasswordEncoder interface. 

```
@Autowired
private PasswordEncoder passwordEncoder;

@Override
@Bean
protected UserDetailsService userDetailsService() {
	UserDetails annaSmith = User.builder()
			.username("annasmith")
			.password(passwordEncoder.encode("password")) 
			.roles("STUDENT") //ROLE
			.build();

	return new InMemoryUserDetailsManager(
		annaSmith
	);
}
```

I have used BCryptPasswordEncoder to encode the password.

**User Permissions:**  
Each role will have set of permissions. (like Read, Write)

We are creating two Roles 
1)STUDENT 2)ADMIN

We created two ENUM, one is for ROLE and PERMISSIONS. (PERMISSIONS will be enrolled as SETS in the ROLE enum).

**Role based Authentication:**  
As per the above design both STUDENT and ADMIN can able to access the same resource /api/v1/students/1, which is not correct. ADMIN cannot access 
STUDENT resource and so we need to stop that by adding Roles to the configure method we wrote earlier.

```
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
			.authorizeRequests()//Authorize Request
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll() // with specific patterns to allow without authentication
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.anyRequest()  //All the Request
			.authenticated() // Must be authenticated
			.and()
			.httpBasic(); //Using Basic Auth Mechanism
}

@Override
@Bean
protected UserDetailsService userDetailsService() {
	UserDetails annaSmithUser = User.builder()
			.username("annasmith")
			.password(passwordEncoder.encode("password"))
			.roles(STUDENT.name()) //ROLE
			.build();

	UserDetails lindaUser = User.builder()
			.username("linda")
			.password(passwordEncoder.encode("password123"))
			.roles(ADMIN.name()) //ROLE
			.build();

	return new InMemoryUserDetailsManager(
		annaSmithUser, lindaUser
	);
}

```
So STUDENT role able to access the /api/** but ADMIN role api access will show as 401 forbidden.

But we have a small issue where the **annasmith** user can access URL for all other student as well. So we need to make sure, each student can access
their details only.

We have two ENUM, 

1)Role 
Roles are STUDENT, ADMIN, ADMINTRAINEE

2)Permissions are STUDENT_READ, STUDENT_WRITE, COURSE_READ, COURSE_WRITE

In the Role ENUM we are mapping the allowed permissions(Sets) as ENUM value. So we need to build a method in Role ENUM which will give us the permission 
for the given Role. In Spring Security we need to give roles and permissions in the GrantedAuthority Interface. Here we need to give implementation for
the interface which is SimpleGrantedAuthority.

```
ApplicationUserRole.java 

public Set<GrantedAuthority> getGrantedAuthorities() {
	Set<GrantedAuthority> permissions = getPermissions().stream()
			.map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
			.collect(Collectors.toSet());
	permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
	return permissions;
}
```

In ApplicationSecurityConfig we have userDetailsService method, in this we need to specify the authorities for each user. previously we have given roles 
in this, because Roles and Permissions will be fetched from the above code. So new code will look like

```
@Override
@Bean
protected UserDetailsService userDetailsService() {
	UserDetails annaSmithUser = User.builder()
			.username("annasmith")
			.password(passwordEncoder.encode("password"))
			//.roles(STUDENT.name()) //ROLE_STUDENT
			.authorities(STUDENT.getGrantedAuthorities())
			.build();

	UserDetails lindaUser = User.builder()
			.username("linda")
			.password(passwordEncoder.encode("password123"))
			//.roles(ADMIN.name()) //ROLE_ADMIN
			.authorities(ADMIN.getGrantedAuthorities())
			.build();

	UserDetails tomUser = User.builder()
			.username("tom")
			.password(passwordEncoder.encode("password123"))
			//.roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
			.authorities(ADMINTRAINEE.getGrantedAuthorities())
			.build();

	return new InMemoryUserDetailsManager(
		annaSmithUser, lindaUser, tomUser
	);
}

```

We have allocated authorities to each user based on their Role. Now in the configure method, we have to control the api access with either hasRole 
method or hasAuthority method.

```
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
			.csrf().disable() //This reason will be explained below. 
			.authorizeRequests()//Authorize Request
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll() // with specific patterns to allow without authentication
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
			.anyRequest()  //All the Request
			.authenticated() // Must be authenticated
			.and()
			.httpBasic(); //Using Basic Auth Mechanism
}
```

Finally we now have implemented the api access by Role and Permissions based Authority.

Note:  
We need to disable CSRF to call the POST, PUT, DELETE methods. Otherwise we will get into 403 forbidden error.

Instead of configuring the antMatchers we can also configure the authorities based on annotation called PreAuthorize.
This annotation will take values in the form like 
hasRole('ROLE_') hasAnyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('permissions')

If we need to enabled this annotation based authority, we need to add the below annotation in the ApplicationSecurityConfig
@EnableGlobalMethodSecurity(prePostEnabled = true)

**CSRF Protection:** Cross Site Request Forgery  
An attacker send a malicious links to user. If the user clicks on the link and when the user logged into Bank site, the malicious attack 
will start to do its work by sending money to the attacker. To prevent this Spring Security will send a CSRF token when the user login to
the server first time. For the subsequent request (PUT, POST, DELETE) the client will send back the CSRF along with request. This time server will 
validate the CSRF first and if its token is valid then will proceed accepting the request or else it will throw 403 forbidden.

**Recommendation:**  
Any request that are processed by a browser by normal user, it should have CSRF protection. For non browser clients its better to disable the CSRF.
We can see Spring CsrfFilter class to find out the implementation of CSRF token, also what are the request http methods can be accessed 
without CSRF token. ("GET", "HEAD", "TRACE", "OPTIONS")

For enabling CSRF token in response cookie after Spring Security 5, we need to set the following config in the WebSecurityConfigurerAdapter
```
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
			.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())//This config must be added to enable to spring to generate CSRF token
			.and()
			.authorizeRequests()//Authorize Request
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll() // with specific patterns to allow without authentication
			.antMatchers("/api/**").hasRole(STUDENT.name())
			//.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
			.anyRequest()  //All the Request
			.authenticated() // Must be authenticated
			.and()
			.httpBasic(); //Using Basic Auth Mechanism
}
```

**HttpOnly Flag:**  
When you set a cookie with the HttpOnly flag, it informs the browser that this special cookie should only be accessed by the server. Any access to the cookie 
from client side script is strictly forbidden. 

CookieCsrfTokenRepository.withHttpOnlyFalse() ==> here we externally set HttpOnly to false, so this CSRF token will be read by the client side scripts.

We can see the response cookie of the first authenticated call will have the CSRF token in the header name XSRF-TOKEN. We can take this token and pass
to the subsequent requests in header with header name as X-XSRF-TOKEN. Now the POST, PUT, DELETE request will be succeeded. 

**Form Based Authentication:**  
To enabled Form Based Authentication we need to simply change formLogin() instead of httpBasic() in ApplicationSecurityConfig configure method. After enabling 
we can see the login screen for authentication. (in the case of httpBasic we got pop-up for asking Username and Password)

When client request login with Username and Password to the server as POST method, we will get a cookie named jsessionid from the server. For the subsequent
request, server will verify this cookie and validate the incoming request. In Spring Security using in memory database to store these cookies.

Validity of jessionid is 30 minutes of inactivity.

```
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
			.csrf().disable()
			.authorizeRequests()//Authorize Request
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll() // with specific patterns to allow without authentication
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.anyRequest()  //All the Request
			.authenticated() // Must be authenticated
			.and()
			//.httpBasic(); //Using Basic Auth Mechanism
			.formLogin()
			.loginPage("/login").permitAll()// Custom Login Page
			.defaultSuccessUrl("/courses", true)	// default landing page after successful login
			.and()
			.rememberMe()	// for maintaining the session for two weeks per user. 
				//.tokenRepository() 
				.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                .key("somethingverystrong"); //Instead of default key we are setting this key to generate a secure MD5 hash
}
```

We need to select remember-me checkbox to send the remember-me value to backend.

RememberMe flag on means then there will be another cookie ("remember-me) created and stored in the inmemory db. So the user session will be maintained for 2 weeks by default.
In the DB the remember-me cookie contains Username, Expiration time and md5 hash of these two values. We can use the tokenValiditySeconds to increase the session time from 
default 2 weeks to higher days. We can our database to get maintain the token and configure using tokenRepository. The remember-me cookie MD5 hash can be generated by 
setting our own key. 

Logout:
We can use the logout URL to logging out from the system.
http://localhost:8080/logout

We can also delete the cookies and session using the below config.

```
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
			.csrf().disable()
			.authorizeRequests()//Authorize Request
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll() // with specific patterns to allow without authentication
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.anyRequest()  //All the Request
			.authenticated() // Must be authenticated
			.and()
			//.httpBasic(); //Using Basic Auth Mechanism
			.formLogin()
			.loginPage("/login").permitAll()
			.defaultSuccessUrl("/courses")
			.and()
			.rememberMe()
				//.tokenRepository()
				.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
				.key("somethingverystrong") //Instead of default key we are setting this key to generate a secure MD5 hash
			.and()
			.logout()
				.logoutUrl("/logout")
				.invalidateHttpSession(true)
				.clearAuthentication(true)
				.deleteCookies("JSESSIONID", "remember-me")
				.logoutSuccessUrl("/login");
}
```

So this configuration will clear out all the cookies during logout.

By default this logout URL will use Http Get method. But as per Http standard whenever the state is changing we should use Http POST method. In the case of logout also 
we should use the POST method.

We can specify our own tag name for username and password and remember-me fields.

```
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
			.csrf().disable()
			.authorizeRequests()//Authorize Request
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll() // with specific patterns to allow without authentication
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.anyRequest()  //All the Request
			.authenticated() // Must be authenticated
			.and()
			//.httpBasic(); //Using Basic Auth Mechanism
			.formLogin()
				.loginPage("/login").permitAll()
				.defaultSuccessUrl("/courses")
				.usernameParameter("username")
				.passwordParameter("password")
			.and()
			.rememberMe()
				//.tokenRepository()
				.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
				.key("somethingverystrong") //Instead of default key we are setting this key to generate a secure MD5 hash
				.rememberMeParameter("remember-me")
			.and()
			.logout()
				.logoutUrl("/logout")
				.invalidateHttpSession(true)
				.clearAuthentication(true)
				.deleteCookies("JSESSIONID", "remember-me")
				.logoutSuccessUrl("/login")
			;
}

```

Database Authentication:  

For configuring the user details from DB, we need to implement the following two methods in ApplicationSecurityConfig. 

```
@Override
protected void configure(AuthenticationManagerBuilder auth) {
	auth.authenticationProvider(daoAuthenticationProvider());
}

@Bean
public DaoAuthenticationProvider daoAuthenticationProvider() {
	DaoAuthenticationProvider provider= new DaoAuthenticationProvider();
	provider.setPasswordEncoder(passwordEncoder);
	provider.setUserDetailsService(applicationUserDetailService);
	return provider;
}
```
In the DaoAuthenticationProvider class we need to set our Custom UserDetailsService class which implements the UserDetailsService. So in this we can call the 
database using spring data jpa and fetch our user roles/permissions.

JWT Authentication:
