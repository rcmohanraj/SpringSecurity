Spring Security Features:

1) Created Simple Bootstrap service with StudentController (commit: Bootstrap Project)  
Service URL: 
http://localhost:8080/api/v1/student/1

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

BasicAuth: (Moving from FormBasedAuth to BasicAuth)
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

Cons: We don't have logout functionality in BasicAuth.

We can add the index.html under resource/static, this will show when we hit URL localhost:8080 instead of showing Whitelabel page

AntMatchers: (Whitelist some URL)
We can Whitelist any specific URL using antMatchers. For example we can Whitelist css, js, root, index.html.
```
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
			.authorizeRequests()//Authorize Request
			.antMatchers("/", "index", "/css/*", "/js/*") // with specific patters
			.permitAll() //to allow without authentication
			.anyRequest()  //All the Request
			.authenticated() // Must be authenticated
			.and()
			.httpBasic(); //Using Basic Auth Mechanism
}
```
