package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/asakuno/huma-sample/app/modules/users"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"gorm.io/gorm"
)

// Repository interface defines the methods for auth repository
type Repository interface {
	// Cognito operations
	SignUp(ctx context.Context, email, username, password string) (*string, error)
	ConfirmSignUp(ctx context.Context, username, confirmationCode string) error
	SignIn(ctx context.Context, username, password string) (*CognitoTokens, error)
	RefreshToken(ctx context.Context, refreshToken string) (*CognitoTokens, error)
	ForgotPassword(ctx context.Context, username string) error
	ConfirmForgotPassword(ctx context.Context, username, confirmationCode, newPassword string) error
	ChangePassword(ctx context.Context, accessToken, currentPassword, newPassword string) error
	SignOut(ctx context.Context, accessToken string) error
	DeleteUser(ctx context.Context, accessToken string) error
	GetUser(ctx context.Context, accessToken string) (*cognitoidentityprovider.GetUserOutput, error)

	// Database operations
	GetUserByEmail(email string) (*users.User, error)
	GetUserByUsername(username string) (*users.User, error)
	GetUserByID(id uint) (*users.User, error)
	CreateUser(user *users.User) error
	UpdateUser(user *users.User) error
	UpdateLastLogin(userID uint) error
}

// AuthRepository implements the Repository interface
type AuthRepository struct {
	db              *gorm.DB
	cognitoClient   *cognitoidentityprovider.Client
	userPoolID      string
	appClientID     string
	appClientSecret string
}

// NewAuthRepository creates a new auth repository
func NewAuthRepository(db *gorm.DB, cognitoClient *cognitoidentityprovider.Client, userPoolID, appClientID, appClientSecret string) Repository {
	return &AuthRepository{
		db:              db,
		cognitoClient:   cognitoClient,
		userPoolID:      userPoolID,
		appClientID:     appClientID,
		appClientSecret: appClientSecret,
	}
}

// SignUp registers a new user with Cognito
func (r *AuthRepository) SignUp(ctx context.Context, email, username, password string) (*string, error) {
	// Always use email as username for local Cognito compatibility
	cognitoUsername := email

	input := &cognitoidentityprovider.SignUpInput{
		ClientId: aws.String(r.appClientID),
		Username: aws.String(cognitoUsername),
		Password: aws.String(password),
		UserAttributes: []types.AttributeType{
			{
				Name:  aws.String("email"),
				Value: aws.String(email),
			},
		},
	}

	if r.appClientSecret != "" {
		input.SecretHash = aws.String(calculateSecretHash(cognitoUsername, r.appClientID, r.appClientSecret))
	}

	output, err := r.cognitoClient.SignUp(ctx, input)
	if err != nil {
		return nil, err
	}

	return output.UserSub, nil
}

// ConfirmSignUp confirms a user's email address
func (r *AuthRepository) ConfirmSignUp(ctx context.Context, username, confirmationCode string) error {
	// Get user by username to find email for Cognito
	user, err := r.GetUserByUsername(username)
	if err != nil {
		return err
	}
	
	// Always use email as cognito username for consistency
	cognitoUsername := user.Email

	input := &cognitoidentityprovider.ConfirmSignUpInput{
		ClientId:         aws.String(r.appClientID),
		Username:         aws.String(cognitoUsername),
		ConfirmationCode: aws.String(confirmationCode),
	}

	if r.appClientSecret != "" {
		input.SecretHash = aws.String(calculateSecretHash(cognitoUsername, r.appClientID, r.appClientSecret))
	}

	_, confirmErr := r.cognitoClient.ConfirmSignUp(ctx, input)
	return confirmErr
}

// SignIn authenticates a user with Cognito
func (r *AuthRepository) SignIn(ctx context.Context, username, password string) (*CognitoTokens, error) {
	// For local Cognito, use email directly as username
	// For production, use the provided username
	cognitoUsername := username
	if r.appClientSecret == "" {
		// This is local Cognito, username is already email
		cognitoUsername = username
	}

	authParams := map[string]string{
		"USERNAME": cognitoUsername,
		"PASSWORD": password,
	}

	if r.appClientSecret != "" {
		authParams["SECRET_HASH"] = calculateSecretHash(cognitoUsername, r.appClientID, r.appClientSecret)
	}

	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeUserPasswordAuth,
		ClientId:       aws.String(r.appClientID),
		AuthParameters: authParams,
	}

	output, err := r.cognitoClient.InitiateAuth(ctx, input)
	if err != nil {
		return nil, err
	}

	if output.AuthenticationResult == nil {
		return nil, errors.New("authentication failed")
	}

	return &CognitoTokens{
		AccessToken:  *output.AuthenticationResult.AccessToken,
		IDToken:      *output.AuthenticationResult.IdToken,
		RefreshToken: *output.AuthenticationResult.RefreshToken,
		ExpiresIn:    output.AuthenticationResult.ExpiresIn,
	}, nil
}

// RefreshToken refreshes the access token using a refresh token
func (r *AuthRepository) RefreshToken(ctx context.Context, refreshToken string) (*CognitoTokens, error) {
	authParams := map[string]string{
		"REFRESH_TOKEN": refreshToken,
	}

	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeRefreshTokenAuth,
		ClientId:       aws.String(r.appClientID),
		AuthParameters: authParams,
	}

	output, err := r.cognitoClient.InitiateAuth(ctx, input)
	if err != nil {
		return nil, err
	}

	if output.AuthenticationResult == nil {
		return nil, errors.New("token refresh failed")
	}

	return &CognitoTokens{
		AccessToken: *output.AuthenticationResult.AccessToken,
		IDToken:     *output.AuthenticationResult.IdToken,
		ExpiresIn:   output.AuthenticationResult.ExpiresIn,
	}, nil
}

// ForgotPassword initiates the forgot password flow
func (r *AuthRepository) ForgotPassword(ctx context.Context, username string) error {
	// Get user by username to find email for Cognito
	user, err := r.GetUserByUsername(username)
	if err != nil {
		return err
	}
	
	// Always use email as cognito username for consistency
	cognitoUsername := user.Email

	input := &cognitoidentityprovider.ForgotPasswordInput{
		ClientId: aws.String(r.appClientID),
		Username: aws.String(cognitoUsername),
	}

	if r.appClientSecret != "" {
		input.SecretHash = aws.String(calculateSecretHash(cognitoUsername, r.appClientID, r.appClientSecret))
	}

	_, forgotErr := r.cognitoClient.ForgotPassword(ctx, input)
	return forgotErr
}

// ConfirmForgotPassword confirms the forgot password with a confirmation code
func (r *AuthRepository) ConfirmForgotPassword(ctx context.Context, username, confirmationCode, newPassword string) error {
	// Get user by username to find email for Cognito
	user, err := r.GetUserByUsername(username)
	if err != nil {
		return err
	}
	
	// Always use email as cognito username for consistency
	cognitoUsername := user.Email

	input := &cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         aws.String(r.appClientID),
		Username:         aws.String(cognitoUsername),
		ConfirmationCode: aws.String(confirmationCode),
		Password:         aws.String(newPassword),
	}

	if r.appClientSecret != "" {
		input.SecretHash = aws.String(calculateSecretHash(cognitoUsername, r.appClientID, r.appClientSecret))
	}

	_, confirmForgotErr := r.cognitoClient.ConfirmForgotPassword(ctx, input)
	return confirmForgotErr
}

// ChangePassword changes the user's password
func (r *AuthRepository) ChangePassword(ctx context.Context, accessToken, currentPassword, newPassword string) error {
	input := &cognitoidentityprovider.ChangePasswordInput{
		AccessToken:      aws.String(accessToken),
		PreviousPassword: aws.String(currentPassword),
		ProposedPassword: aws.String(newPassword),
	}

	_, err := r.cognitoClient.ChangePassword(ctx, input)
	return err
}

// SignOut signs out a user
func (r *AuthRepository) SignOut(ctx context.Context, accessToken string) error {
	input := &cognitoidentityprovider.GlobalSignOutInput{
		AccessToken: aws.String(accessToken),
	}

	_, err := r.cognitoClient.GlobalSignOut(ctx, input)
	return err
}

// DeleteUser deletes a user from Cognito
func (r *AuthRepository) DeleteUser(ctx context.Context, accessToken string) error {
	input := &cognitoidentityprovider.DeleteUserInput{
		AccessToken: aws.String(accessToken),
	}

	_, err := r.cognitoClient.DeleteUser(ctx, input)
	return err
}

// GetUser gets user information from Cognito
func (r *AuthRepository) GetUser(ctx context.Context, accessToken string) (*cognitoidentityprovider.GetUserOutput, error) {
	input := &cognitoidentityprovider.GetUserInput{
		AccessToken: aws.String(accessToken),
	}

	return r.cognitoClient.GetUser(ctx, input)
}

// Database operations

// GetUserByEmail retrieves a user by email
func (r *AuthRepository) GetUserByEmail(email string) (*users.User, error) {
	ctx := context.Background()
	user, err := gorm.G[users.User](r.db).Where("email = ?", email).First(ctx)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (r *AuthRepository) GetUserByUsername(username string) (*users.User, error) {
	ctx := context.Background()
	user, err := gorm.G[users.User](r.db).Where("name = ?", username).First(ctx)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByID retrieves a user by ID
func (r *AuthRepository) GetUserByID(id uint) (*users.User, error) {
	ctx := context.Background()
	user, err := gorm.G[users.User](r.db).Where("id = ?", id).First(ctx)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// CreateUser creates a new user in the database
func (r *AuthRepository) CreateUser(user *users.User) error {
	ctx := context.Background()
	return gorm.G[users.User](r.db).Create(ctx, user)
}

// UpdateUser updates a user in the database
func (r *AuthRepository) UpdateUser(user *users.User) error {
	ctx := context.Background()
	_, err := gorm.G[users.User](r.db).Where("id = ?", user.ID).Updates(ctx, *user)
	return err
}

// UpdateLastLogin updates the last login timestamp
func (r *AuthRepository) UpdateLastLogin(userID uint) error {
	ctx := context.Background()
	now := time.Now()
	_, err := gorm.G[users.User](r.db).Where("id = ?", userID).Update(ctx, "last_login_at", &now)
	return err
}

// Helper function to calculate secret hash for Cognito
func calculateSecretHash(username, clientID, clientSecret string) string {
	message := username + clientID
	key := []byte(clientSecret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
