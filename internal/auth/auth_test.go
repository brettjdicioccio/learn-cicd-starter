package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "No Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Empty Authorization Header",
			headers: http.Header{
				"Authorization": {""},
			},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: http.Header{
				"Authorization": {"Bearer somekey"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": {"ApiKey myapikey"},
			},
			expectedKey: "myapikey",
			expectedErr: nil,
		},
		{
			name: "Invalid Authorization Scheme",
			headers: http.Header{
				"Authorization": {"ApiKey"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %s, got %s", tt.expectedKey, key)
			}

			if (err != nil && tt.expectedErr == nil) || (err == nil && tt.expectedErr != nil) {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			} else if err != nil && tt.expectedErr != nil && err.Error() != tt.expectedErr.Error() {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}
