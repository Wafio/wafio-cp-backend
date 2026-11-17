package geo

import (
	"sort"
	"strings"
)

// CountryName returns full country name in English for ISO 3166-1 alpha-2 code. Empty for unknown or "—".
func CountryName(code string) string {
	if code == "" || code == "—" {
		return ""
	}
	upper := strings.ToUpper(strings.TrimSpace(code))
	if upper == "XX" || upper == "ZZ" {
		return "Unknown / Private"
	}
	if name, ok := countryNames[upper]; ok {
		return name
	}
	return ""
}

// ValidCountryCode returns true if code is a valid ISO 3166-1 alpha-2 country code (e.g. ID, US). Case-insensitive.
func ValidCountryCode(code string) bool {
	if len(code) != 2 {
		return false
	}
	upper := strings.ToUpper(strings.TrimSpace(code))
	_, ok := countryNames[upper]
	return ok
}

// AllCountryCodes returns all valid ISO 3166-1 alpha-2 codes in sorted order (for API/UI).
func AllCountryCodes() []string {
	codes := make([]string, 0, len(countryNames))
	for c := range countryNames {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return codes
}

// CountryCodesWithNames returns a map of code -> name for all countries (for UI dropdown/list).
func CountryCodesWithNames() map[string]string {
	out := make(map[string]string, len(countryNames))
	for k, v := range countryNames {
		out[k] = v
	}
	return out
}

var countryNames = map[string]string{
	"AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan", "AG": "Antigua and Barbuda",
	"AI": "Anguilla", "AL": "Albania", "AM": "Armenia", "AO": "Angola", "AR": "Argentina",
	"AT": "Austria", "AU": "Australia", "AW": "Aruba", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina",
	"BB": "Barbados", "BD": "Bangladesh", "BE": "Belgium", "BF": "Burkina Faso", "BG": "Bulgaria",
	"BH": "Bahrain", "BI": "Burundi", "BJ": "Benin", "BN": "Brunei", "BO": "Bolivia",
	"BR": "Brazil", "BS": "Bahamas", "BT": "Bhutan", "BW": "Botswana", "BY": "Belarus",
	"BZ": "Belize", "CA": "Canada", "CD": "Democratic Republic of the Congo", "CF": "Central African Republic",
	"CG": "Republic of the Congo", "CH": "Switzerland", "CI": "Ivory Coast", "CL": "Chile",
	"CM": "Cameroon", "CN": "China", "CO": "Colombia", "CR": "Costa Rica", "CU": "Cuba",
	"CV": "Cape Verde", "CY": "Cyprus", "CZ": "Czech Republic", "DE": "Germany", "DJ": "Djibouti",
	"DK": "Denmark", "DM": "Dominica", "DO": "Dominican Republic", "DZ": "Algeria", "EC": "Ecuador",
	"EE": "Estonia", "EG": "Egypt", "ER": "Eritrea", "ES": "Spain", "ET": "Ethiopia",
	"FI": "Finland", "FJ": "Fiji", "FR": "France", "GA": "Gabon", "GB": "United Kingdom",
	"GD": "Grenada", "GE": "Georgia", "GH": "Ghana", "GM": "Gambia", "GN": "Guinea",
	"GQ": "Equatorial Guinea", "GR": "Greece", "GT": "Guatemala", "GW": "Guinea-Bissau", "GY": "Guyana",
	"HK": "Hong Kong", "HN": "Honduras", "HR": "Croatia", "HT": "Haiti", "HU": "Hungary",
	"ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IN": "India", "IQ": "Iraq",
	"IR": "Iran", "IS": "Iceland", "IT": "Italy", "JM": "Jamaica", "JO": "Jordan",
	"JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia", "KI": "Kiribati",
	"KM": "Comoros", "KN": "Saint Kitts and Nevis", "KP": "North Korea", "KR": "South Korea",
	"KW": "Kuwait", "KZ": "Kazakhstan", "LA": "Laos", "LB": "Lebanon", "LC": "Saint Lucia",
	"LI": "Liechtenstein", "LK": "Sri Lanka", "LR": "Liberia", "LS": "Lesotho", "LT": "Lithuania",
	"LU": "Luxembourg", "LV": "Latvia", "LY": "Libya", "MA": "Morocco", "MC": "Monaco",
	"MD": "Moldova", "ME": "Montenegro", "MG": "Madagascar", "MK": "North Macedonia", "ML": "Mali",
	"MM": "Myanmar", "MN": "Mongolia", "MO": "Macau", "MR": "Mauritania", "MT": "Malta",
	"MU": "Mauritius", "MV": "Maldives", "MW": "Malawi", "MX": "Mexico", "MY": "Malaysia",
	"MZ": "Mozambique", "NA": "Namibia", "NE": "Niger", "NG": "Nigeria", "NI": "Nicaragua",
	"NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NZ": "New Zealand", "OM": "Oman",
	"PA": "Panama", "PE": "Peru", "PG": "Papua New Guinea", "PH": "Philippines", "PK": "Pakistan",
	"PL": "Poland", "PR": "Puerto Rico", "PS": "Palestine", "PT": "Portugal", "PY": "Paraguay",
	"QA": "Qatar", "RO": "Romania", "RS": "Serbia", "RU": "Russia", "RW": "Rwanda",
	"SA": "Saudi Arabia", "SB": "Solomon Islands", "SC": "Seychelles", "SD": "Sudan",
	"SE": "Sweden", "SG": "Singapore", "SI": "Slovenia", "SK": "Slovakia", "SL": "Sierra Leone",
	"SM": "San Marino", "SN": "Senegal", "SO": "Somalia", "SR": "Suriname", "SS": "South Sudan",
	"ST": "São Tomé and Príncipe", "SV": "El Salvador", "SY": "Syria", "SZ": "Eswatini",
	"TD": "Chad", "TG": "Togo", "TH": "Thailand", "TJ": "Tajikistan", "TL": "Timor-Leste",
	"TM": "Turkmenistan", "TN": "Tunisia", "TO": "Tonga", "TR": "Turkey", "TT": "Trinidad and Tobago",
	"TW": "Taiwan", "TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda", "US": "United States",
	"UY": "Uruguay", "UZ": "Uzbekistan", "VA": "Vatican City", "VE": "Venezuela", "VN": "Vietnam",
	"VU": "Vanuatu", "WS": "Samoa", "YE": "Yemen", "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe",
}
