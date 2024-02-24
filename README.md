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
    ``` http://127.0.0.1:8000/api/auth/register/ 
        
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
```
3. Authorization of token
   a. Mechanism of sending token along with a request from client to service
   b. Should check for expiry
   c. Error handling (proper error codes in each failure scenario)
4. Revocation of token
   a. Mechanism of revoking a token from backend
5. Mechanism to refresh a token
   a. Client should be able to renew the token before it expires