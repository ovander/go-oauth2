package service

import (
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// GeoIPResult contains geographic information for an IP address
type GeoIPResult struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp,omitempty"`
	IsValid     bool    `json:"is_valid"`
}

// GeoIPService provides IP geolocation functionality
type GeoIPService interface {
	Lookup(ipAddress string) *GeoIPResult
	LookupBatch(ipAddresses []string) map[string]*GeoIPResult
	IsConfigured() bool
	Close() error
}

type geoIPService struct {
	cityDB     *geoip2.Reader
	asnDB      *geoip2.Reader
	mu         sync.RWMutex
	configured bool
}

// GeoIPConfig holds configuration for GeoIP service
type GeoIPConfig struct {
	CityDBPath string // Path to GeoLite2-City.mmdb
	ASNDBPath  string // Path to GeoLite2-ASN.mmdb (optional, for ISP info)
}

// NewGeoIPService creates a new GeoIP service
func NewGeoIPService(config GeoIPConfig) GeoIPService {
	service := &geoIPService{
		configured: false,
	}

	// Try to open City database
	if config.CityDBPath != "" {
		cityDB, err := geoip2.Open(config.CityDBPath)
		if err != nil {
			logger.Warnf("GeoIP City database not available: %v", err)
		} else {
			service.cityDB = cityDB
			service.configured = true
			logger.Info("GeoIP City database loaded successfully")
		}
	}

	// Try to open ASN database (optional)
	if config.ASNDBPath != "" {
		asnDB, err := geoip2.Open(config.ASNDBPath)
		if err != nil {
			logger.Warnf("GeoIP ASN database not available: %v", err)
		} else {
			service.asnDB = asnDB
			logger.Info("GeoIP ASN database loaded successfully")
		}
	}

	if !service.configured {
		logger.Warn("GeoIP service running in fallback mode (no database configured)")
	}

	return service
}

// NewGeoIPServiceDisabled creates a disabled GeoIP service (fallback mode)
func NewGeoIPServiceDisabled() GeoIPService {
	return &geoIPService{
		configured: false,
	}
}

// Lookup returns geographic information for an IP address
func (s *geoIPService) Lookup(ipAddress string) *GeoIPResult {
	result := &GeoIPResult{
		IP:      ipAddress,
		IsValid: false,
	}

	// Parse IP
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return result
	}

	// Skip private/local IPs
	if isPrivateIP(ip) {
		result.CountryCode = "LO"
		result.CountryName = "Local Network"
		result.City = "Private IP"
		result.IsValid = true
		return result
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// If no database configured, return unknown
	if s.cityDB == nil {
		result.CountryCode = "XX"
		result.CountryName = "Unknown"
		result.City = "Unknown"
		result.IsValid = true
		return result
	}

	// Lookup in City database
	cityRecord, err := s.cityDB.City(ip)
	if err != nil {
		result.CountryCode = "XX"
		result.CountryName = "Unknown"
		result.City = "Unknown"
		result.IsValid = true
		return result
	}

	result.CountryCode = cityRecord.Country.IsoCode
	result.CountryName = cityRecord.Country.Names["en"]
	result.Latitude = cityRecord.Location.Latitude
	result.Longitude = cityRecord.Location.Longitude
	result.Timezone = cityRecord.Location.TimeZone
	result.IsValid = true

	// Get city name
	if len(cityRecord.City.Names) > 0 {
		result.City = cityRecord.City.Names["en"]
	} else {
		result.City = "Unknown"
	}

	// Get region/subdivision
	if len(cityRecord.Subdivisions) > 0 {
		result.Region = cityRecord.Subdivisions[0].Names["en"]
	}

	// Lookup ISP if ASN database available
	if s.asnDB != nil {
		asnRecord, err := s.asnDB.ASN(ip)
		if err == nil {
			result.ISP = asnRecord.AutonomousSystemOrganization
		}
	}

	return result
}

// LookupBatch performs batch lookup for multiple IP addresses
func (s *geoIPService) LookupBatch(ipAddresses []string) map[string]*GeoIPResult {
	results := make(map[string]*GeoIPResult, len(ipAddresses))
	for _, ip := range ipAddresses {
		results[ip] = s.Lookup(ip)
	}
	return results
}

// IsConfigured returns true if GeoIP database is available
func (s *geoIPService) IsConfigured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configured
}

// Close closes the GeoIP databases
func (s *geoIPService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	if s.cityDB != nil {
		err = s.cityDB.Close()
		s.cityDB = nil
	}
	if s.asnDB != nil {
		if closeErr := s.asnDB.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		s.asnDB = nil
	}
	s.configured = false
	return err
}

// isPrivateIP checks if an IP is private/local
func isPrivateIP(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, block := range privateBlocks {
		_, cidr, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
