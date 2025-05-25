package cognito

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

// Custom errors
var (
	ErrMissingRegion     = errors.New("AWS region is required")
	ErrMissingUserPoolID = errors.New("Cognito user pool ID is required")
	ErrMissingClientID   = errors.New("Cognito client ID is required")
	ErrInvalidConfig     = errors.New("invalid Cognito configuration")
)

// Client wraps the AWS Cognito Identity Provider client
type Client struct {
	cognitoClient *cognitoidentityprovider.Client
	config        *Config
}

// NewClient creates a new Cognito client
func NewClient(ctx context.Context, cfg *Config) (*Client, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Load AWS SDK configuration
	sdkConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.Region),
	)
	if err != nil {
		return nil, err
	}

	// Create Cognito client
	cognitoClient := cognitoidentityprovider.NewFromConfig(sdkConfig)

	return &Client{
		cognitoClient: cognitoClient,
		config:        cfg,
	}, nil
}

// GetCognitoClient returns the underlying Cognito client
func (c *Client) GetCognitoClient() *cognitoidentityprovider.Client {
	return c.cognitoClient
}

// GetConfig returns the Cognito configuration
func (c *Client) GetConfig() *Config {
	return c.config
}

// UserPoolID returns the configured user pool ID
func (c *Client) UserPoolID() string {
	return c.config.UserPoolID
}

// ClientID returns the configured client ID
func (c *Client) ClientID() string {
	return c.config.ClientID
}

// ClientSecret returns the configured client secret
func (c *Client) ClientSecret() string {
	return c.config.ClientSecret
}

// HasClientSecret returns true if client secret is configured
func (c *Client) HasClientSecret() bool {
	return c.config.ClientSecret != ""
}
