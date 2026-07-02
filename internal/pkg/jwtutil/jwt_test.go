package jwtutil

import (
	"testing"
	"time"
)

func TestGenerateAndParseToken(t *testing.T) {
	secret := "test-secret"
	tokenString, err := GenerateToken(secret, 42, "admin", 1)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	claims, err := ParseToken(secret, tokenString)
	if err != nil {
		t.Fatalf("ParseToken() error = %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
	if claims.Role != "admin" {
		t.Errorf("Role = %q, want %q", claims.Role, "admin")
	}
}

func TestParseToken_WrongSecret(t *testing.T) {
	tokenString, err := GenerateToken("secret-a", 1, "admin", 1)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	_, err = ParseToken("secret-b", tokenString)
	if err == nil {
		t.Fatal("ParseToken() expected error for wrong secret, got nil")
	}
}

func TestParseToken_Expired(t *testing.T) {
	secret := "test-secret"
	tokenString, err := GenerateToken(secret, 1, "admin", 0)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	time.Sleep(1 * time.Second)

	_, err = ParseToken(secret, tokenString)
	if err == nil {
		t.Fatal("ParseToken() expected error for expired token, got nil")
	}
}
