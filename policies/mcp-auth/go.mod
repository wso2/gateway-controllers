module github.com/wso2/gateway-controllers/policies/mcp-auth

go 1.25.1

require github.com/wso2/api-platform/sdk v0.3.1

require github.com/wso2/gateway-controllers/policies/jwt-auth v0.1.0

require github.com/golang-jwt/jwt/v5 v5.2.2 // indirect

replace github.com/wso2/gateway-controllers/policies/jwt-auth => ../jwt-auth
