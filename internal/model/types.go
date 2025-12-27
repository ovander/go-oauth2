package model

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

// StringArray is a custom type for PostgreSQL text[] arrays
type StringArray []string

// Scan implements sql.Scanner interface for reading from database
func (a *StringArray) Scan(src interface{}) error {
	if src == nil {
		*a = nil
		return nil
	}

	var str string
	switch v := src.(type) {
	case []byte:
		str = string(v)
	case string:
		str = v
	default:
		return fmt.Errorf("cannot scan %T into StringArray", src)
	}

	// Handle empty array
	if str == "{}" {
		*a = StringArray{}
		return nil
	}

	// Remove the curly braces
	str = strings.TrimPrefix(str, "{")
	str = strings.TrimSuffix(str, "}")

	if str == "" {
		*a = StringArray{}
		return nil
	}

	// Parse the array elements
	var result []string
	var current strings.Builder
	inQuotes := false
	escaped := false

	for i := 0; i < len(str); i++ {
		c := str[i]

		if escaped {
			current.WriteByte(c)
			escaped = false
			continue
		}

		switch c {
		case '\\':
			escaped = true
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				result = append(result, current.String())
				current.Reset()
			} else {
				current.WriteByte(c)
			}
		default:
			current.WriteByte(c)
		}
	}

	// Don't forget the last element
	if current.Len() > 0 || len(result) > 0 {
		result = append(result, current.String())
	}

	*a = result
	return nil
}

// Value implements driver.Valuer interface for writing to database
func (a StringArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}

	if len(a) == 0 {
		return "{}", nil
	}

	// Build PostgreSQL array literal
	var sb strings.Builder
	sb.WriteByte('{')

	for i, s := range a {
		if i > 0 {
			sb.WriteByte(',')
		}
		// Quote and escape the string
		sb.WriteByte('"')
		for _, c := range s {
			if c == '"' || c == '\\' {
				sb.WriteByte('\\')
			}
			sb.WriteRune(c)
		}
		sb.WriteByte('"')
	}

	sb.WriteByte('}')
	return sb.String(), nil
}
