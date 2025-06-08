/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// getTokenCmd represents the getToken command
var getTokenCmd = &cobra.Command{
	Use:   "get-token",
	Short: "This command gets GitHub user token via device authorization grant.",
	Long: `This command uses device authorization grant of GitHub Apps. 
It requires GitHub Apps to initiate device authorization request.
The detailed description is here:
https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow
	`,
	Run: func(cmd *cobra.Command, args []string) {

		clientID := viper.GetString("client_id")
		scope := strings.ReplaceAll(viper.GetString("scope"), ",", " ")

		userCode, uri, deviceCode, err := initiateDeviceAuthorization(clientID, scope)
		if err != nil {
			cmd.PrintErrf("failed to initiate device authorization grant: %v", err)
			return
		}

		cmd.Println("device authorization grant is requrested. Please signin from uri and enter user_code as below.")
		cmd.Println("uri: ", uri)
		cmd.Println("user_code: ", userCode)

		accessToken, err := pollDeviceAuthorizationGrantToken(clientID, deviceCode)
		if err != nil {
			cmd.PrintErrf("failed to poll device authorization grant token: %v", err)
			return
		}

		cmd.Println("success to get user access token")
		cmd.Println(accessToken)
	},
}

func init() {
	rootCmd.AddCommand(getTokenCmd)

	getTokenCmd.Flags().String("client_id", "", "required: github app client id")
	getTokenCmd.Flags().String("scope", "public_repo", "comma-separated scope values which are granted")

	getTokenCmd.MarkFlagRequired("client_id")

	_ = viper.BindPFlag("client_id", getTokenCmd.Flags().Lookup("client_id"))
	_ = viper.BindPFlag("scope", getTokenCmd.Flags().Lookup("scope"))
}

const (
	authzEndpoint = "https://github.com/login/device/code"
	tokenEndpoint = "https://github.com/login/oauth/access_token"
	deviceGrant   = "urn:ietf:params:oauth:grant-type:device_code"
)

func initiateDeviceAuthorization(clientID, scope string) (string, string, string, error) {
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("scope", scope)

	req, err := http.NewRequest("POST", authzEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return "", "", "", err
	}

	client := http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", err
	}

	r, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", "", err
	}

	userCode := r.Get("user_code")
	uri := r.Get("verification_uri")
	deviceCode := r.Get("device_code")

	return userCode, uri, deviceCode, nil
}

func pollDeviceAuthorizationGrantToken(clientID, deviceCode string) (string, error) {
	start := time.Now()

	for time.Since(start) < 1*time.Minute {
		values := url.Values{}
		values.Set("client_id", clientID)
		values.Set("device_code", deviceCode)
		values.Set("grant_type", deviceGrant)
		req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(values.Encode()))
		if err != nil {
			return "", err
		}
		client := http.Client{}
		res, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer res.Body.Close()

		b, err := io.ReadAll(res.Body)
		if err != nil {
			return "", err
		}

		parsed, err := url.ParseQuery(string(b))
		if err != nil {
			return "", err
		}

		if parsed.Get("access_token") != "" {
			return parsed.Get("access_token"), err
		}

		switch parsed.Get("error") {
		case "authorization_pending":
			time.Sleep(5 * time.Second)
			continue

		case "slow_down":
			interval := parsed.Get("interval")
			i, err := strconv.Atoi(interval)
			if err != nil {
				return "", err
			}
			time.Sleep(time.Duration(i) * time.Second)
			continue

		default:
			return "", fmt.Errorf("failed to poll device authorization: %v", parsed.Get("error"))
		}
	}

	return "", fmt.Errorf("timeout")
}
