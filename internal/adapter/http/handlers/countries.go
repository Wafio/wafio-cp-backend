package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/shared/geo"
)

// CountryCodes returns all valid ISO 3166-1 alpha-2 country codes and names for UI (e.g. Allow/Block Countries).
func CountryCodes(c *fiber.Ctx) error {
	codes := geo.AllCountryCodes()
	names := geo.CountryCodesWithNames()
	list := make([]fiber.Map, 0, len(codes))
	for _, code := range codes {
		list = append(list, fiber.Map{"code": code, "name": names[code]})
	}
	return c.JSON(fiber.Map{"codes": codes, "list": list})
}
