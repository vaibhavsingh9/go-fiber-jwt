package controllers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/vaibhavsingh9/go-fiber-jwt/models"
)

func GetMe(c *fiber.Ctx) error {
	user := c.Locals("user").(models.UserResponse)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "data": fiber.Map{"user": user}})
}
