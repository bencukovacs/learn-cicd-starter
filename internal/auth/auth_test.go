package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedAPIKey string
		expectedError  error
	}{
		{
			name: "valid authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123def456"},
			},
			expectedAPIKey: "abc123def456",
			expectedError:  nil,
		},
		{
			name:           "missing authorization header",
			headers:        http.Header{},
			expectedAPIKey: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedAPIKey: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123def456"},
			},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name: "malformed header - only ApiKey without value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name: "malformed header - empty after ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedAPIKey: "",
			expectedError:  nil,
		},
		{
			name: "case sensitive ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"apikey abc123def456"},
			},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name: "multiple spaces between ApiKey and value",
			headers: http.Header{
				"Authorization": []string{"ApiKey  abc123def456"},
			},
			expectedAPIKey: "",
			expectedError:  nil,
		},
		{
			name: "api key with special characters",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc-123_def.456"},
			},
			expectedAPIKey: "abc-123_def.456",
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing case: %s", tt.name)
			t.Logf("Input headers: %+v", tt.headers)

			apiKey, err := GetAPIKey(tt.headers)

			t.Logf("Got apiKey: '%s'", apiKey)
			t.Logf("Got error: %v", err)
			t.Logf("Expected apiKey: '%s'", tt.expectedAPIKey)
			t.Logf("Expected error: %v", tt.expectedError)

			// Check API key
			if apiKey != tt.expectedAPIKey {
				t.Errorf("GetAPIKey() apiKey = '%v', want '%v'", apiKey, tt.expectedAPIKey)
			} else {
				t.Logf("✅ API key matches expected value")
			}

			// Check error
			if tt.expectedError == nil {
				if err != nil {
					t.Errorf("GetAPIKey() error = %v, want nil", err)
				} else {
					t.Logf("✅ No error as expected")
				}
			} else {
				if err == nil {
					t.Errorf("GetAPIKey() error = nil, want %v", tt.expectedError)
				} else if err.Error() != tt.expectedError.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedError)
				} else {
					t.Logf("✅ Error matches expected value")
				}
			}
			t.Logf("--- End of test case: %s ---\n", tt.name)
		})
	}
}

// Benchmark test
func BenchmarkGetAPIKey(b *testing.B) {
	headers := http.Header{
		"Authorization": []string{"ApiKey abc123def456"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetAPIKey(headers)
	}
}
