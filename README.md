# JWT

Reference taken from [BLOG](https://codevoweb.com/how-to-properly-use-jwt-for-authentication-in-golang/#google_vignette)

Run docker image
```
docker-compose up -d
```
To Run:
```
go get ./
go run main.go
```
1. Sign up (creation of user) using email and password: 
    ``` 
   http://127.0.0.1:8000/api/auth/register/ 
   {
      "name":"First",
      "email":"first@gmail.com",
      "password":"123456789",
      "passwordconfirm":"123456789"
   }
   ```

 
2. Sign in
   a. Authentication of user credentials
   b. A token is returned as response preferably JWT
```
    http://127.0.0.1:8000/api/auth/login/
    
    {
        "name":"First",
        "email":"first@gmail.com",
    }
```
3. Authorization of token
   a. Mechanism of sending token along with a request from client to service
         -> Tokens sent as cookies
   b. Should check for expiry
         -> Validate function in [token.go](https://github.com/vaibhavsingh9/go-fiber-jwt/blob/main/utils/token.go)
   c. Error handling (proper error codes in each failure scenario)
4. 
4. Revocation of token
   a. Mechanism of revoking a token from backend
         -> Unable to implement

5. Mechanism to refresh a token
   a. Client should be able to renew the token before it expires
         -> Implemented

Used frameworks and libraries:
   1. [Fiber](https://docs.gofiber.io/)
   2. [Gorm](https://gorm.io/docs/index.html)
   3. [Viper](https://blog.logrocket.com/handling-go-configuration-viper/)
   4. [JWT](https://pkg.go.dev/github.com/golang-jwt/jwt/v4)
   5. [Validators](https://pkg.go.dev/github.com/go-playground/validator/v10)
   6. [Go-Redis](https://redis.io/docs/connect/clients/go/) 
   7. [Postgres](https://blog.logrocket.com/building-simple-app-go-postgresql/)