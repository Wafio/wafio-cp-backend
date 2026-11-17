// Package validate provides a shared validator and helpers for request validation.
package validate

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

var v = validator.New()

// Struct validates s and returns the first validation error as a readable message, or nil.
func Struct(s interface{}) error {
	err := v.Struct(s)
	if err == nil {
		return nil
	}
	if errs, ok := err.(validator.ValidationErrors); ok && len(errs) > 0 {
		e := errs[0]
		field := e.Field()
		msg := fieldToMessage(e.Tag(), e.Param())
		fieldLabel := field
		if len(field) > 0 {
			fieldLabel = strings.ToLower(field[:1]) + field[1:]
		}
		return fmt.Errorf("%s: %s", fieldLabel, msg)
	}
	return err
}

func fieldToMessage(tag, param string) string {
	switch tag {
	case "required":
		return "is required"
	case "email":
		return "must be a valid email"
	case "min":
		return "must be at least " + param + " character(s)"
	case "max":
		return "must be at most " + param + " character(s)"
	case "oneof":
		return "must be one of: " + param
	case "gte":
		return "must be >= " + param
	case "lte":
		return "must be <= " + param
	default:
		return "is invalid"
	}
}
