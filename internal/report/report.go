package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nats-io/jwt/v2"
	"go.uber.org/zap"
)

type connzResponse struct {
	NumConnections int `json:"num_connections"`
	Connections    []struct {
		Account        string `json:"account"`
		Name           string `json:"name"`
		IP             string `json:"ip"`
		Subscriptions  int    `json:"subscriptions"`
		InMsgs         int64  `json:"in_msgs"`
		OutMsgs        int64  `json:"out_msgs"`
		AuthorizedUser string `json:"authorized_user"`
	} `json:"connections"`
}

// Run executes the full NATS credential report.
func Run(log *zap.Logger, monitorURL, credsFile, tlsCA string) error {
	log.Info("starting credential health check")

	if err := reportVarz(log, monitorURL); err != nil {
		log.Warn("varz check failed", zap.Error(err))
	}

	// Fetch connz once for use by both accountz auth callout checks and connz report.
	connz, err := fetchConnz(monitorURL)
	if err != nil {
		log.Warn("connz fetch failed", zap.Error(err))
	}

	if err := reportAccountz(log, monitorURL, connz); err != nil {
		log.Warn("accountz check failed", zap.Error(err))
	}

	reportConnz(log, connz)

	log.Info("check complete")
	return nil
}

func reportVarz(log *zap.Logger, monitorURL string) error {
	body, err := httpGet(monitorURL + "/varz")
	if err != nil {
		return err
	}

	var varz struct {
		ServerID    string `json:"server_id"`
		ServerName  string `json:"server_name"`
		Version     string `json:"version"`
		Uptime      string `json:"uptime"`
		Connections int    `json:"connections"`
		AuthErrors  int64  `json:"auth_errors"`
	}
	if err := json.Unmarshal(body, &varz); err != nil {
		return fmt.Errorf("parse varz: %w", err)
	}

	log.Info("server stats",
		zap.String("server_name", varz.ServerName),
		zap.String("server_id", varz.ServerID[:12]),
		zap.String("version", varz.Version),
		zap.String("uptime", varz.Uptime),
		zap.Int("connections", varz.Connections),
		zap.Int64("auth_errors", varz.AuthErrors),
	)
	return nil
}

func reportAccountz(log *zap.Logger, monitorURL string, connz *connzResponse) error {
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
			log.Error("failed to fetch account details",
				zap.String("account_id", accID[:12]),
				zap.Error(err),
			)
			continue
		}

		var detail struct {
			AccountDetail struct {
				AccountName string `json:"account_name"`
				Expired     bool   `json:"expired"`
				Complete    bool   `json:"complete"`
				JetStream   bool   `json:"jetstream_enabled"`
				Connections int    `json:"client_connections"`
				LeafNodes   int    `json:"leafnode_connections"`
				JWTString   string `json:"jwt"`
			} `json:"account_detail"`
		}
		if err := json.Unmarshal(detailBody, &detail); err != nil {
			log.Error("failed to parse account details",
				zap.String("account_id", accID[:12]),
				zap.Error(err),
			)
			continue
		}

		d := detail.AccountDetail
		accLog := log.With(zap.String("account", d.AccountName))

		status := "OK"
		if d.Expired {
			status = "EXPIRED"
		}

		accLog.Info("account status",
			zap.String("status", status),
			zap.Int("connections", d.Connections),
			zap.Int("leaf_nodes", d.LeafNodes),
			zap.Bool("jetstream", d.JetStream),
			zap.Bool("complete", d.Complete),
		)

		if d.JWTString == "" {
			continue
		}

		claims, err := jwt.DecodeAccountClaims(d.JWTString)
		if err != nil {
			accLog.Warn("JWT decode error", zap.Error(err))
			continue
		}

		reportJWTExpiry(accLog, claims)
		checkAuthCallout(accLog, claims, connz)
	}

	return nil
}

func reportJWTExpiry(log *zap.Logger, claims *jwt.AccountClaims) {
	issuedAt := time.Unix(claims.IssuedAt, 0)

	if claims.Expires > 0 {
		expiresAt := time.Unix(claims.Expires, 0)
		remaining := time.Until(expiresAt)
		daysRemaining := remaining.Hours() / 24

		log.Info("JWT expiry",
			zap.Time("issued_at", issuedAt),
			zap.Time("expires_at", expiresAt),
			zap.Float64("days_remaining", daysRemaining),
		)
		if remaining < 30*24*time.Hour {
			log.Warn("JWT expires soon", zap.Float64("days_remaining", daysRemaining))
		}
	} else {
		log.Info("JWT expiry",
			zap.Time("issued_at", issuedAt),
			zap.String("expires", "never"),
		)
	}
}

func checkAuthCallout(log *zap.Logger, claims *jwt.AccountClaims, connz *connzResponse) {
	if !claims.Account.HasExternalAuthorization() {
		return
	}

	authUsers := claims.Account.Authorization.AuthUsers
	log.Info("auth callout configured", zap.Int("auth_users", len(authUsers)))

	if connz == nil {
		log.Warn("cannot verify auth callout user connectivity — connz unavailable")
		return
	}

	for _, authUserID := range authUsers {
		found := false
		for _, conn := range connz.Connections {
			if conn.AuthorizedUser == authUserID {
				found = true
				break
			}
		}

		displayID := authUserID
		if len(displayID) > 12 {
			displayID = displayID[:12]
		}

		if !found {
			log.Warn("auth callout user is NOT connected — non-auth connections will timeout",
				zap.String("auth_user_id", displayID),
			)
		} else {
			log.Info("auth callout user connected",
				zap.String("auth_user_id", displayID),
			)
		}
	}
}

func fetchConnz(monitorURL string) (*connzResponse, error) {
	body, err := httpGet(monitorURL + "/connz?limit=256&auth=true")
	if err != nil {
		return nil, err
	}

	var connz connzResponse
	if err := json.Unmarshal(body, &connz); err != nil {
		return nil, fmt.Errorf("parse connz: %w", err)
	}

	return &connz, nil
}

func reportConnz(log *zap.Logger, connz *connzResponse) {
	if connz == nil {
		log.Warn("connz report skipped — data unavailable")
		return
	}

	log.Info("active connections", zap.Int("total", connz.NumConnections))

	// Group by account
	byAccount := make(map[string]int)
	for _, c := range connz.Connections {
		byAccount[c.Account]++
	}
	for acc, count := range byAccount {
		log.Info("connections by account",
			zap.String("account", acc),
			zap.Int("count", count),
		)
	}

	// List individual connections
	for _, c := range connz.Connections {
		name := c.Name
		if name == "" {
			name = c.IP
		}
		log.Info("connection",
			zap.String("account", c.Account),
			zap.String("name", name),
			zap.Int("subscriptions", c.Subscriptions),
			zap.Int64("in_msgs", c.InMsgs),
			zap.Int64("out_msgs", c.OutMsgs),
		)
	}
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
