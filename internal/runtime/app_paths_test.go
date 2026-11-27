package runtime

import "testing"

func TestGvxAppDevelopmentSocketHasOneCanonicalRoot(t *testing.T) {
	host := HostConfig{StorageRoot: "/var/lib/chatanium/storage", ManagementDirectory: "/var/lib/chatanium/storage/app"}
	if err := host.ValidateDevelopmentSocket("/var/lib/chatanium/storage/app/native/control.sock"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/var/tmp/control.sock", "/var/lib/chatanium/app/native/control.sock", "/var/lib/chatanium/storage/app/native-other/control.sock", "/var/lib/chatanium/storage/app/native/nested/control.sock", "/var/lib/chatanium/storage/app/native/../control.sock"} {
		if host.ValidateDevelopmentSocket(path) == nil {
			t.Fatal("development socket escaped canonical native direct-child policy")
		}
	}
	host.ManagementDirectory = "/var/lib/chatanium/app"
	if host.ValidateDevelopmentSocket("/var/lib/chatanium/storage/app/native/control.sock") == nil {
		t.Fatal("legacy unaccounted management alias accepted")
	}
}
