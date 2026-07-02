package manifest

import "testing"

func TestParseAPK_HelloWorld(t *testing.T) {
	info, err := ParseAPK("testdata/helloworld.apk")
	if err != nil {
		t.Fatalf("ParseAPK() error = %v", err)
	}
	if info.PackageName != "com.example.helloworld" {
		t.Errorf("PackageName = %q, want %q", info.PackageName, "com.example.helloworld")
	}
}

func TestParseAPK_NotAnAPK(t *testing.T) {
	_, err := ParseAPK("testdata/not-an-apk.txt")
	if err == nil {
		t.Fatal("expected error for invalid apk file, got nil")
	}
}
