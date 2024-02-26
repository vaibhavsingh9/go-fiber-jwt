package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/vaibhavsingh9/go-fiber-jwt/initializers"
	"github.com/vaibhavsingh9/go-fiber-jwt/models"
	"github.com/vaibhavsingh9/go-fiber-jwt/utils"
	"golang.org/x/net/context"
	"gorm.io/gorm"
	"strings"
)

func DeserializeUser(c *fiber.Ctx) error {
	var access_token string
	authorization := c.Get("Authorization")

	if strings.HasPrefix(authorization, "Bearer ") {
		access_token = strings.TrimPrefix(authorization, "Bearer ")
	} else if c.Cookies("access_token") != "" {
		access_token = c.Cookies("access_token")
	}
	if access_token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "fail", "message": "You are not logged in"})
	}
	config, _ := initializers.LoadConfig(".")
	tokenClaims, err := utils.ValidateToken(access_token, config.AccessTokenPublicKey)
	if err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"status": "fail", "message": err.Error()})
	}
	ctx := context.Background()
	userid, err := initializers.RedisClient.Get(ctx, tokenClaims.TokenUuid).Result()
	if err == redis.Nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"status": "fail", "message": "Token is invalid or session has expired"})
	}
	var user models.User
	err = initializers.DB.First(&user, "id = ?", userid).Error

	if err == gorm.ErrRecordNotFound {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"status": "fail", "message": "the user belonging to this token no logger exists"})
	}
	//user and access_token_uuid are stored in fiber context which can
	//be used throughout the api, it will be used for logout route as well.
	c.Locals("user", models.FilterUserRecord(&user))
	c.Locals("access_token_uuid", tokenClaims.TokenUuid)

	return c.Next()
}
