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

