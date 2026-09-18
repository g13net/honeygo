package geoip

import (
	"encoding/json"
	"fmt"
	"honeygo/internal/db"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

type GeoInfo struct {
	CountryCode string
	CountryName string
	ASN         string
	ASName      string
	Netblock    string
}

type Resolver struct {
	mmdb     *geoip2.Reader
	memCache sync.Map
}

func NewResolver() *Resolver {
	r := &Resolver{}
	// Try to load local MMDB if provided
	if _, err := os.Stat("GeoLite2-Country.mmdb"); err == nil {
		reader, err := geoip2.Open("GeoLite2-Country.mmdb")
		if err == nil {
			r.mmdb = reader
		}
	}
	return r
}

func (r *Resolver) Close() {
	if r.mmdb != nil {
		r.mmdb.Close()
	}
}

func (r *Resolver) Resolve(ip string) (string, string, string, string, string) {
	// Clean port if present
	if cleanIP, _, err := net.SplitHostPort(ip); err == nil {
		ip = cleanIP
	}

	if ip == "" {
		return "LCL", "Local Network", "", "Local Machine", "127.0.0.0/8"
	}

	// 1. Check In-Memory Fast Cache
	if val, ok := r.memCache.Load(ip); ok {
		info := val.(GeoInfo)
		return info.CountryCode, info.CountryName, info.ASN, info.ASName, info.Netblock
	}

	// Check loopback / private IP
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		if parsedIP.IsLoopback() {
			info := GeoInfo{CountryCode: "LCL", CountryName: "Local Network", ASN: "", ASName: "Local Machine", Netblock: "127.0.0.0/8"}
			r.memCache.Store(ip, info)
			return info.CountryCode, info.CountryName, info.ASN, info.ASName, info.Netblock
		}
		if parsedIP.IsPrivate() {
			info := GeoInfo{CountryCode: "PRV", CountryName: "Private Network", ASN: "", ASName: "Private LAN", Netblock: ""}
			r.memCache.Store(ip, info)
			if db.DB != nil {
				db.DB.Create(&db.GeoCache{
					IP:          ip,
					CountryCode: "PRV",
					CountryName: "Private Network",
					ASN:         "",
					ASName:      "Private LAN",
					Netblock:    "",
					CreatedAt:   time.Now(),
				})
			}
			return info.CountryCode, info.CountryName, info.ASN, info.ASName, info.Netblock
		}
	}

	// 2. Check Local DB Cache
	if db.DB != nil {
		var cache db.GeoCache
		if err := db.DB.Where("ip = ?", ip).First(&cache).Error; err == nil && cache.CountryCode != "" {
			info := GeoInfo{
				CountryCode: cache.CountryCode,
				CountryName: cache.CountryName,
				ASN:         cache.ASN,
				ASName:      cache.ASName,
				Netblock:    cache.Netblock,
			}
			r.memCache.Store(ip, info)
			return info.CountryCode, info.CountryName, info.ASN, info.ASName, info.Netblock
		}
	}

	var code, name, asn, asname, netblock string

	// 3. Try Local MMDB (Fast offline lookup)
	if r.mmdb != nil && parsedIP != nil {
		record, err := r.mmdb.Country(parsedIP)
		if err == nil && record.Country.IsoCode != "" {
			code = record.Country.IsoCode
			name = record.Country.Names["en"]
			asname = name
		}
	}

	// 4. Default to Unknown if not found (Never block the hot write path with external HTTP API calls)
	if code == "" {
		code = "UN"
		name = "Unknown"
		asname = "Unknown"
	}

	info := GeoInfo{
		CountryCode: code,
		CountryName: name,
		ASN:         asn,
		ASName:      asname,
		Netblock:    netblock,
	}
	r.memCache.Store(ip, info)

	if db.DB != nil {
		db.DB.Create(&db.GeoCache{
			IP:          ip,
			CountryCode: code,
			CountryName: name,
			ASN:         asn,
			ASName:      asname,
			Netblock:    netblock,
			CreatedAt:   time.Now(),
		})
	}

	return code, name, asn, asname, netblock
}

func (r *Resolver) ResolveSync(ip string) (string, string, string, string, string) {
	code, name, asn, asname, netblock := r.Resolve(ip)
	if code != "UN" && code != "" {
		return code, name, asn, asname, netblock
	}

	apiCode, apiName, apiAsn, apiAsname, apiNetblock := r.resolveViaAPI(ip)
	if apiCode != "" {
		info := GeoInfo{
			CountryCode: apiCode,
			CountryName: apiName,
			ASN:         apiAsn,
			ASName:      apiAsname,
			Netblock:    apiNetblock,
		}
		r.memCache.Store(ip, info)
		if db.DB != nil {
			db.DB.Model(&db.GeoCache{}).Where("ip = ?", ip).Updates(map[string]interface{}{
				"country_code": apiCode,
				"country_name": apiName,
				"asn":          apiAsn,
				"as_name":      apiAsname,
				"netblock":     apiNetblock,
			})
		}
		return apiCode, apiName, apiAsn, apiAsname, apiNetblock
	}
	return code, name, asn, asname, netblock
}

func (r *Resolver) resolveViaAPI(ip string) (string, string, string, string, string) {
	// Fields: status, country, countryCode, as, org, zip
	// "as" usually contains "AS1234 Company Name"
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,as,org", ip)
	
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", "", "", "", ""
	}
	defer resp.Body.Close()

	var result struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		AS          string `json:"as"`
		Org         string `json:"org"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", "", ""
	}

	if result.Status == "success" {
		asn := ""
		asname := result.Org
		if strings.HasPrefix(result.AS, "AS") {
			parts := strings.SplitN(result.AS, " ", 2)
			asn = parts[0]
			if asname == "" && len(parts) > 1 {
				asname = parts[1]
			}
		}

		// ip-api doesn't give netblock directly in this free tier usually, 
		// but let's assume Org is what they want for "ownership"
		// and ASN is the block identifier.
		return result.CountryCode, result.Country, asn, asname, "" 
	}

	return "", "", "", "", ""
}

// LookupASNCymru queries Team Cymru DNS (AS<num>.asn.cymru.com) to retrieve the official RIR-registered ASN country and holder
func LookupASNCymru(asn string) (countryCode string, asHolder string) {
	cleanASN := strings.ToUpper(strings.TrimSpace(asn))
	if !strings.HasPrefix(cleanASN, "AS") {
		cleanASN = "AS" + cleanASN
	}
	txts, err := net.LookupTXT(cleanASN + ".asn.cymru.com")
	if err != nil || len(txts) == 0 {
		return "", ""
	}
	// Cymru TXT format: "208137 | RO | ripencc | 2025-08-05 | FPS12 - Feo Prest SRL, RO"
	parts := strings.Split(txts[0], "|")
	if len(parts) >= 2 {
		countryCode = strings.TrimSpace(parts[1])
	}
	if len(parts) >= 5 {
		asHolder = strings.TrimSpace(parts[4])
	}
	return countryCode, asHolder
}

// StartAutoResolver runs in background to resolve any records missing country info
func (r *Resolver) StartAutoResolver() {
	go func() {
		for {
			if db.DB == nil {
				time.Sleep(5 * time.Second)
				continue
			}

			var attempts []db.Attempt
			db.DB.Where("country_code = '' OR country_code = 'UN' OR country_code IS NULL").Limit(10).Find(&attempts)

			for _, a := range attempts {
				code, name, asn, asname, netblock := r.ResolveSync(a.RemoteIP)
				if code != "" {
					db.DB.Model(&a).Updates(map[string]interface{}{
						"country_code": code,
						"country_name": name,
						"asn":          asn,
						"as_name":      asname,
						"netblock":     netblock,
					})
				}
				// Throttle bulk lookups to avoid API bans
				time.Sleep(2 * time.Second)
			}

			var creds []db.Credential
			db.DB.Where("country_code = '' OR country_code = 'UN' OR country_code IS NULL").Limit(10).Find(&creds)
			for _, c := range creds {
				code, name, asn, asname, netblock := r.ResolveSync(c.RemoteIP)
				if code != "" {
					db.DB.Model(&c).Updates(map[string]interface{}{
						"country_code": code,
						"country_name": name,
						"asn":          asn,
						"as_name":      asname,
						"netblock":     netblock,
					})
				}
				time.Sleep(2 * time.Second)
			}

			time.Sleep(30 * time.Second)
		}
	}()
}
