package cognito

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/asakuno/huma-sample/auth/domain/entity"
	"github.com/asakuno/huma-sample/auth/domain/repository"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// authRepository implements the AuthRepository interface
type authRepository struct {
	client *Client
}

// NewAuthRepository creates a new AuthRepository
func NewAuthRepository(client *Client) repository.AuthRepository {
	return &authRepository{
		client: client,
	}
}

// Authenticate authenticates a user with username and password
func (r *authRepository) Authenticate(ctx context.Context, req *repository.CognitoAuthRequest) (*repository.CognitoAuthResponse, error) {
	if req == nil {
		return nil, errors.New("authentication request is required")
	}

	// Prepare authentication parameters
	authParams := map[string]string{
		"USERNAME": req.Username,
		"PASSWORD": req.Password,
	}

	// Add SECRET_HASH if client secret is configured
	if r.client.HasClientSecret() {
		secretHash := r.calculateSecretHash(req.Username)
		authParams["SECRET_HASH"] = secretHash
	}

	// Initiate authentication
	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeUserPasswordAuth,
		ClientId:       aws.String(r.client.ClientID()),
		AuthParameters: authParams,
	}

	output, err := r.client.GetCognitoClient().InitiateAuth(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Handle challenges (e.g., NEW_PASSWORD_REQUIRED, MFA)
	if output.ChallengeName != "" {
		return nil, fmt.Errorf("authentication challenge required: %s", output.ChallengeName)
	}

	if output.AuthenticationResult == nil {
		return nil, errors.New("authentication result is empty")
	}

	return &repository.CognitoAuthResponse{
		AccessToken:  aws.ToString(output.AuthenticationResult.AccessToken),
		RefreshToken: aws.ToString(output.AuthenticationResult.RefreshToken),
		IDToken:      aws.ToString(output.AuthenticationResult.IdToken),
		TokenType:    "Bearer",
		ExpiresIn:    int(output.AuthenticationResult.ExpiresIn),
	}, nil
}

// RefreshToken refreshes an access token using a refresh token
func (r *authRepository) RefreshToken(ctx context.Context, refreshToken string) (*repository.CognitoAuthResponse, error) {
	if refreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	authParams := map[string]string{
		"REFRESH_TOKEN": refreshToken,
	}

	// Add SECRET_HASH if client secret is configured
	// Note: For refresh token, we need the username, but it's not available here
	// In a real implementation, you might need to decode the refresh token or store the username
	if r.client.HasClientSecret() {
		// This is a limitation - we need the username for SECRET_HASH
		// In practice, you might store this information or decode it from the token
		return nil, errors.New("refresh token with client secret requires username")
	}

	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeRefreshTokenAuth,
		ClientId:       aws.String(r.client.ClientID()),
		AuthParameters: authParams,
	}

	output, err := r.client.GetCognitoClient().InitiateAuth(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	if output.AuthenticationResult == nil {
		return nil, errors.New("authentication result is empty")
	}

	return &repository.CognitoAuthResponse{
		AccessToken:  aws.ToString(output.AuthenticationResult.AccessToken),
		RefreshToken: aws.ToString(output.AuthenticationResult.RefreshToken),
		IDToken:      aws.ToString(output.AuthenticationResult.IdToken),
		TokenType:    "Bearer",
		ExpiresIn:    int(output.AuthenticationResult.ExpiresIn),
	}, nil
}

// GetUserInfo retrieves user information from Cognito using access token
func (r *authRepository) GetUserInfo(ctx context.Context, accessToken string) (*repository.CognitoUserInfo, error) {
	if accessToken == "" {
		return nil, errors.New("access token is required")
	}

	input := &cognitoidentityprovider.GetUserInput{
		AccessToken: aws.String(accessToken),
	}

	output, err := r.client.GetCognitoClient().GetUser(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	userInfo := &repository.CognitoUserInfo{
		Sub:      aws.ToString(output.Username), // In Cognito, Username is actually the sub (user ID)
		Username: aws.ToString(output.Username),
		Status:   string(output.UserStatus),
	}

	// Parse user attributes
	for _, attr := range output.UserAttributes {
		switch aws.ToString(attr.Name) {
		case "email":
			userInfo.Email = aws.ToString(attr.Value)
		case "given_name":
			userInfo.FirstName = aws.ToString(attr.Value)
		case "family_name":
			userInfo.LastName = aws.ToString(attr.Value)
		case "sub":
			userInfo.Sub = aws.ToString(attr.Value)
		}
	}

	return userInfo, nil
}

// ValidateToken validates an access token
func (r *authRepository) ValidateToken(ctx context.Context, accessToken string) (*entity.TokenClaims, error) {
	if accessToken == "" {
		return nil, errors.New("access token is required")
	}

	// Parse JWT token without verification (we'll verify with Cognito)
	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Verify token by calling GetUser (this validates the token with Cognito)
	userInfo, err := r.GetUserInfo(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Extract claims
	tokenClaims := &entity.TokenClaims{
		CognitoID: userInfo.Sub,
		Username:  userInfo.Username,
		Email:     userInfo.Email,
		Issuer:    getStringClaim(claims, "iss"),
		Audience:  getStringClaim(claims, "aud"),
	}

	// Parse timestamps
	if exp, ok := claims["exp"].(float64); ok {
		tokenClaims.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if iat, ok := claims["iat"].(float64); ok {
		tokenClaims.IssuedAt = time.Unix(int64(iat), 0)
	}

	// Parse user ID if available (this might be stored in custom claims)
	if userIDStr := getStringClaim(claims, "custom:user_id"); userIDStr != "" {
		if userID, err := uuid.Parse(userIDStr); err == nil {
			tokenClaims.UserID = userID
		}
	}

	return tokenClaims, nil
}

// SignOut signs out a user by invalidating their tokens
func (r *authRepository) SignOut(ctx context.Context, accessToken string) error {
	if accessToken == "" {
		return errors.New("access token is required")
	}

	input := &cognitoidentityprovider.GlobalSignOutInput{
		AccessToken: aws.String(accessToken),
	}

	_, err := r.client.GetCognitoClient().GlobalSignOut(ctx, input)
	if err != nil {
		return fmt.Errorf("sign out failed: %w", err)
	}

	return nil
}

// ForgotPassword initiates the forgot password flow
func (r *authRepository) ForgotPassword(ctx context.Context, req *repository.ForgotPasswordRequest) error {
	if req == nil || req.Username == "" {
		return errors.New("username is required")
	}

	input := &cognitoidentityprovider.ForgotPasswordInput{
		ClientId: aws.String(r.client.ClientID()),
		Username: aws.String(req.Username),
	}

	// Add SECRET_HASH if client secret is configured
	if r.client.HasClientSecret() {
		secretHash := r.calculateSecretHash(req.Username)
		input.SecretHash = aws.String(secretHash)
	}

	_, err := r.client.GetCognitoClient().ForgotPassword(ctx, input)
	if err != nil {
		return fmt.Errorf("forgot password failed: %w", err)
	}

	return nil
}

// ConfirmForgotPassword confirms the forgot password with verification code
func (r *authRepository) ConfirmForgotPassword(ctx context.Context, req *repository.ConfirmForgotPasswordRequest) error {
	if req == nil {
		return errors.New("confirm forgot password request is required")
	}

	input := &cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         aws.String(r.client.ClientID()),
		Username:         aws.String(req.Username),
		ConfirmationCode: aws.String(req.ConfirmationCode),
		Password:         aws.String(req.NewPassword),
	}

	// Add SECRET_HASH if client secret is configured
	if r.client.HasClientSecret() {
		secretHash := r.calculateSecretHash(req.Username)
		input.SecretHash = aws.String(secretHash)
	}

	_, err := r.client.GetCognitoClient().ConfirmForgotPassword(ctx, input)
	if err != nil {
		return fmt.Errorf("confirm forgot password failed: %w", err)
	}

	return nil
}

// CreateUser creates a new user in Cognito (admin operation)
func (r *authRepository) CreateUser(ctx context.Context, username, email, tempPassword string) error {
	input := &cognitoidentityprovider.AdminCreateUserInput{
		UserPoolId:    aws.String(r.client.UserPoolID()),
		Username:      aws.String(username),
		MessageAction: types.MessageActionTypeSuppress,
		TemporaryPassword: aws.String(tempPassword),
		UserAttributes: []types.AttributeType{
			{
				Name:  aws.String("email"),
				Value: aws.String(email),
			},
			{
				Name:  aws.String("email_verified"),
				Value: aws.String("true"),
			},
		},
	}

	_, err := r.client.GetCognitoClient().AdminCreateUser(ctx, input)
	if err != nil {
		return fmt.Errorf("create user failed: %w", err)
	}

	return nil
}

// SetUserPassword sets a permanent password for a user (admin operation)
func (r *authRepository) SetUserPassword(ctx context.Context, username, password string) error {
	input := &cognitoidentityprovider.AdminSetUserPasswordInput{
		UserPoolId: aws.String(r.client.UserPoolID()),
		Username:   aws.String(username),
		Password:   aws.String(password),
		Permanent:  true,
	}

	_, err := r.client.GetCognitoClient().AdminSetUserPassword(ctx, input)
	if err != nil {
		return fmt.Errorf("set user password failed: %w", err)
	}

	return nil
}

// DeleteUser deletes a user from Cognito (admin operation)
func (r *authRepository) DeleteUser(ctx context.Context, username string) error {
	input := &cognitoidentityprovider.AdminDeleteUserInput{
		UserPoolId: aws.String(r.client.UserPoolID()),
		Username:   aws.String(username),
	}

	_, err := r.client.GetCognitoClient().AdminDeleteUser(ctx, input)
	if err != nil {
		return fmt.Errorf("delete user failed: %w", err)
	}

	return nil
}

// ListUsers lists users from Cognito with pagination
func (r *authRepository) ListUsers(ctx context.Context, limit int, paginationToken string) ([]*repository.CognitoUserInfo, string, error) {
	input := &cognitoidentityprovider.ListUsersInput{
		UserPoolId: aws.String(r.client.UserPoolID()),
		Limit:      aws.Int32(int32(limit)),
	}

	if paginationToken != "" {
		input.PaginationToken = aws.String(paginationToken)
	}

	output, err := r.client.GetCognitoClient().ListUsers(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("list users failed: %w", err)
	}

	var users []*repository.CognitoUserInfo
	for _, user := range output.Users {
		userInfo := &repository.CognitoUserInfo{
			Username: aws.ToString(user.Username),
			Status:   string(user.UserStatus),
		}

		// Parse user attributes
		for _, attr := range user.Attributes {
			switch aws.ToString(attr.Name) {
			case "sub":
				userInfo.Sub = aws.ToString(attr.Value)
			case "email":
				userInfo.Email = aws.ToString(attr.Value)
			case "given_name":
				userInfo.FirstName = aws.ToString(attr.Value)
			case "family_name":
				userInfo.LastName = aws.ToString(attr.Value)
			}
		}

		users = append(users, userInfo)
	}

	nextToken := ""
	if output.PaginationToken != nil {
		nextToken = aws.ToString(output.PaginationToken)
	}

	return users, nextToken, nil
}

// calculateSecretHash calculates the SECRET_HASH for Cognito client authentication
func (r *authRepository) calculateSecretHash(username string) string {
	message := username + r.client.ClientID()
	h := hmac.New(sha256.New, []byte(r.client.ClientSecret()))
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// getStringClaim safely extracts a string claim from JWT claims
func getStringClaim(claims jwt.MapClaims, key string) string {
	if value, ok := claims[key].(string); ok {
		return value
	}
	return ""
}
