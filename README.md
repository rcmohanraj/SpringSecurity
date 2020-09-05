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

**JWT Authentication and Authorizations:**(JAWT as pronunciation) JSON Web Tokens  
JSON tokens exchange over the web.
Fast  
Stateless  
Used across many services  

**Why JWT:**  
Traditionally server authenticates client based on tokens (SessionId+cookie). These session id are maintained by server in the session log. Once the client is authenticated
the server will generate a session id and send it across to the client. Now the browser will send back the session id in the subsequent requests, so that the server will verify
it from its own session log. 

The issue here is, it will work only for big monolith kind of applications. When the application has to be deployed in multiple servers with load balancer in front of them, then 
the client will hit only the load balancer. Load balancer will decide which server to connect based on some random algorithm, also each server will maintain their own session 
log. For example if client is authenticated by server1 then this session will be maintained by server1 session log, for the subsequent request if the load balancer redirects to the server2 instead of server1 then the current session id is not present in session log of server2. In this case the client request will be failed and server will ask for authentication.

For solving this cases we have two solutions.  
**1) Shared Session Cache across all the servers (Example: Redis Cache)**  
This will maintain the session across the servers and each server will validate the session against the common cached session log. In this way we can avoid asking the client to 
authenticate again. But here we got another problem that is Single Point of Failure. If this cache failures all the clients session will be invalidated. 

**2) Sticky Session:**  
Once the client is authenticated the load balancer maintains an attribute between client and server like client IP or cookie. Based on this attributes the load balancer will always forward the request of authenticated clients to the same physical server. The problem here is scalability, when one server goes down, entire session log associated with server will
be destroyed. The client has to authenticate again.

For solving these issues JWT came into play.
JWT is stateless and session-less. These tokens are signed tokens sent by the server. Whenever the client is authenticated, the server will generate JSON web token using clients username(can be called as principal or subject) and client information by signing with secret key. Can be sent in cookies.

**JWT Structure:Separated by periods(.)**  
Header . Payload . Signature

1) Header => it will have the type of algorithm used to encrypt. Header will be encoded as Base64 string. 

2) Payload => is the actual json data will be encoded as Base64 string. 

3) Signature => It's the actual value signed by server with secret key by combining header+payload. Here the secret key knows to the server only. 

JWT not only for Web applications, it can be given to any kind of clients to access the service from the server.

**Step 1:** Client sends username and password to server.  
**Step 2:** Server authenticate the client username and password.   
**Step 3:** Now server will create JWT for future Authorizations.  
**Step 4:** Server will send the JWT to the client.  
**Step 5:** Client will store this in local storage or cookie.  
**Step 6:** Client will pass the JWT in the subsequent request by adding this JWT to the request header. (header key Authorization and header value begins with (Bearer +JWT))  
**Step 7:** Server will get the JWT from request header and calculate the signature by combining the encoded header+payload with the secret key and verify against with the incoming signature.  

**Notes:**
1. No confidential information about users should not be present in the payload
2. If someone steals the JWT, then make request to the server, now the server will authorizes JWT without knowing its from wrong user because the JWT is valid. So we need to transfer via HTTPS and need to use with other Authentication and Authorization mechanism's like OAUTH.
3. Sessionid can be validated if we know the sessionid has stolen by someone because its present in server. But in the case of JWT, when we know someone steals the JWT, we will not be able to invalidate because the server always verify the JWT signature is correct. To overcome this we need to have blacklisted JWT's in the database. We can verify this against the DB.


**OAuth 2.0: Auth stands for Authorization**
Authorization works between services.
Access Delegation

Here token is used by OAuth is JWT.

Terms in OAuth Roles:  
1) Resource or Protected Resource ==> resource or files the user holds
2) Resource Owner ==> person to the access resource (user)
3) Resource Server ==> server hosting the protected resource (example google drive)
4) Client ==> Application thats making request to protected resource on behalf of the resource owner
5) Authorization Server ==> managed by Resource Server and coupled together with Resource Server. This server will issue access tokens

OAuth Flows:  
Flow 1:
1) Resource Owners asks Client to get the Resource from Resource Server
2) Client will check with Authorization Server to get the permissions
3) Authorization Server will ask the Resource Owner to validate the credentials
4) Once the Authorization Server validates the Resource Owner credentials, Authorization Server will give Authorization token to Client
5) Client will contact Authorization Server with this Authorization Token to get the Access Token
6) Authorization Server will issue the Access Token to Client based on the Authorization Token (Short lived token)
7) Client will send the Access Token to Resource Server to access the Resource
8) Resource Server verify the Access Token with Authorization Server
9) Once Access Token is validated, Resource Server will issue access to the Resource to Client

Exchange between the Authorization Token and Access Token happening in secure way. So there is no way to steal the Access Token.

Flow 2: Implicit Flow
Its same as Flow 1 but the place where the Authorization Server will not give Authorization Token and Access Token. Instead it will directly give Access Token.

Drawback of Flow 2: If someone get hold of the Access Token then they can access the Resource Server.

Flow 3: Client Credential Flow.
Works between Micro Services where the Client is trustworthy. When Service1 calls an Api to Service2. Both services are written by us. Then Service1 is the 
trustworthy. Here Service2 will have the burden to maintain the Security.

1) Service1 as a Client makes a call to the Authorization Server to get the Access Token
2) Authorization Server will issue the Access Token to Service1
3) Service1 use this Access Token to make calls to Service2 where Service2 will authorize the request from Service1 by using the Access Token.

