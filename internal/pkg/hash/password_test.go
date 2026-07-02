package hash

import "testing"

func TestHashAndCheckPassword(t *testing.T) {
	hashed, err := HashPassword("MySecret123!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if hashed == "MySecret123!" {
		t.Error("hashed password must not equal plaintext")
	}

	if !CheckPassword(hashed, "MySecret123!") {
		t.Error("CheckPassword() = false, want true for correct password")
	}
	if CheckPassword(hashed, "WrongPassword") {
		t.Error("CheckPassword() = true, want false for wrong password")
	}
}
