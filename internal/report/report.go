package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nats-io/jwt/v2"
)

// Run executes the full NATS credential report.
func Run(monitorURL, credsFile, tlsCA string) error {
	fmt.Printf("=== NATS Credential Health Check %s ===\n", time.Now().Format(time.RFC3339))

	if err := reportVarz(monitorURL); err != nil {
		fmt.Printf("WARN: varz check failed: %v\n", err)
	}

	if err := reportAccountz(monitorURL); err != nil {
		fmt.Printf("WARN: accountz check failed: %v\n", err)
	}

	if err := reportConnz(monitorURL); err != nil {
		fmt.Printf("WARN: connz check failed: %v\n", err)
	}

	fmt.Println("=== Check Complete ===")
	return nil
}

func reportVarz(monitorURL string) error {
	fmt.Println("--- Server Stats (varz) ---")

	body, err := httpGet(monitorURL + "/varz")
	if err != nil {
		return err
	}

	var varz struct {
		ServerID   string `json:"server_id"`
		ServerName string `json:"server_name"`
		Version    string `json:"version"`
		Uptime     string `json:"uptime"`
		Connections int   `json:"connections"`
		AuthErrors int64  `json:"auth_errors"`
	}
	if err := json.Unmarshal(body, &varz); err != nil {
		return fmt.Errorf("parse varz: %w", err)
	}

	fmt.Printf("  Server: %s (%s) v%s\n", varz.ServerName, varz.ServerID[:12], varz.Version)
	fmt.Printf("  Uptime: %s\n", varz.Uptime)
	fmt.Printf("  Connections: %d\n", varz.Connections)
	fmt.Printf("  Auth Errors: %d\n", varz.AuthErrors)
	return nil
}

func reportAccountz(monitorURL string) error {
	fmt.Println("--- Account Status (accountz) ---")

	body, err := httpGet(monitorURL + "/accountz")
	if err != nil {
		return err
	}

	var accountz struct {
		Accounts []string `json:"accounts"`
	}
	if err := json.Unmarshal(body, &accountz); err != nil {
		return fmt.Errorf("parse accountz: %w", err)
	}

	for _, accID := range accountz.Accounts {
		detailBody, err := httpGet(fmt.Sprintf("%s/accountz?acc=%s", monitorURL, accID))
		if err != nil {
			fmt.Printf("  %s: ERROR fetching details: %v\n", accID[:12], err)
			continue
		}

		var detail struct {
			AccountDetail struct {
				AccountName string `json:"account_name"`
				Expired     bool   `json:"expired"`
				Complete    bool   `json:"complete"`
				JetStream   bool   `json:"jetstream_enabled"`
				Connections int    `json:"num_connections"`
				LeafNodes   int    `json:"num_leaf_nodes"`
			} `json:"account_detail"`
		}
		if err := json.Unmarshal(detailBody, &detail); err != nil {
			fmt.Printf("  %s: ERROR parsing details: %v\n", accID[:12], err)
			continue
		}

		d := detail.AccountDetail
		status := "OK"
		if d.Expired {
			status = "EXPIRED"
		}

		fmt.Printf("  %-15s [%s] conns=%d leafs=%d js=%v complete=%v\n",
			d.AccountName, status, d.Connections, d.LeafNodes, d.JetStream, d.Complete)

		reportAccountJWTExpiry(monitorURL, accID, d.AccountName)
	}

	return nil
}

func reportAccountJWTExpiry(monitorURL, accID, accName string) {
	body, err := httpGet(fmt.Sprintf("%s/accountz?acc=%s", monitorURL, accID))
	if err != nil {
		return
	}

	var raw struct {
		AccountDetail struct {
			JWTString string `json:"jwt"`
		} `json:"account_detail"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || raw.AccountDetail.JWTString == "" {
		return
	}

	claims, err := jwt.DecodeAccountClaims(raw.AccountDetail.JWTString)
	if err != nil {
		fmt.Printf("    JWT decode error: %v\n", err)
		return
	}

	issuedAt := time.Unix(claims.IssuedAt, 0)
	fmt.Printf("    Issued: %s\n", issuedAt.Format(time.RFC3339))

	if claims.Expires > 0 {
		expiresAt := time.Unix(claims.Expires, 0)
		remaining := time.Until(expiresAt)
		fmt.Printf("    Expires: %s (in %.0f days)\n", expiresAt.Format(time.RFC3339), remaining.Hours()/24)
		if remaining < 30*24*time.Hour {
			fmt.Printf("    WARNING: Account %s JWT expires in less than 30 days!\n", accName)
		}
	} else {
		fmt.Printf("    Expires: never\n")
	}
}

func reportConnz(monitorURL string) error {
	fmt.Println("--- Active Connections (connz) ---")

	body, err := httpGet(monitorURL + "/connz?limit=256")
	if err != nil {
		return err
	}

	var connz struct {
		NumConnections int `json:"num_connections"`
		Connections    []struct {
			Account       string `json:"account"`
			Name          string `json:"name"`
			IP            string `json:"ip"`
			Subscriptions int    `json:"subscriptions"`
			InMsgs        int64  `json:"in_msgs"`
			OutMsgs       int64  `json:"out_msgs"`
		} `json:"connections"`
	}
	if err := json.Unmarshal(body, &connz); err != nil {
		return fmt.Errorf("parse connz: %w", err)
	}

	fmt.Printf("  Total connections: %d\n", connz.NumConnections)

	// Group by account
	byAccount := make(map[string]int)
	for _, c := range connz.Connections {
		byAccount[c.Account]++
	}
	for acc, count := range byAccount {
		fmt.Printf("    %-20s %d connections\n", acc, count)
	}

	// List individual connections
	for _, c := range connz.Connections {
		name := c.Name
		if name == "" {
			name = c.IP
		}
		fmt.Printf("    [%s] %s subs=%d in=%d out=%d\n",
			c.Account, name, c.Subscriptions, c.InMsgs, c.OutMsgs)
	}

	return nil
}

func httpGet(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
