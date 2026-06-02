package cmd

import "testing"

func TestLooksLikeHookPayload(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"plain text", "DB_PASSWORD=value", false},
		{"valid hook payload", `{"tool_name":"Bash","tool_response":{"stdout":"x"}}`, true},
		{"leading whitespace + valid", "  \n\t" + `{"tool_name":"Bash"}`, true},
		{"ruby hash literal", `{"SID"=>"adasdsadasda12345"}`, false},
		{"php array literal", `{"key" => "value"}`, false},
		{"unclosed brace", `{"tool_name":"Bash"`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := looksLikeHookPayload([]byte(c.in))
			if got != c.want {
				t.Errorf("looksLikeHookPayload(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
