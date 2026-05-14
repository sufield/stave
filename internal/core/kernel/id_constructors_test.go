package kernel

import "testing"

// Each constructor enforces a single rule: the raw value must be
// non-empty. The format itself (hash, SID, URI, snake_case_name) is
// out of scope — those shapes are enforced at their derivation sites.
// The constructor is the boundary-check for callers that already hold
// a derived value but might be passing an accidentally-empty string.
func TestIDConstructors_RejectEmpty(t *testing.T) {
	t.Run("NewChainID", func(t *testing.T) {
		if _, err := NewChainID(""); err == nil {
			t.Fatalf("NewChainID(\"\") = nil, want error")
		}
	})
	t.Run("NewFindingID", func(t *testing.T) {
		if _, err := NewFindingID(""); err == nil {
			t.Fatalf("NewFindingID(\"\") = nil, want error")
		}
	})
	t.Run("NewIssueID", func(t *testing.T) {
		if _, err := NewIssueID(""); err == nil {
			t.Fatalf("NewIssueID(\"\") = nil, want error")
		}
	})
	t.Run("NewStatementID", func(t *testing.T) {
		if _, err := NewStatementID(""); err == nil {
			t.Fatalf("NewStatementID(\"\") = nil, want error")
		}
	})
	t.Run("NewGranteeID", func(t *testing.T) {
		if _, err := NewGranteeID(""); err == nil {
			t.Fatalf("NewGranteeID(\"\") = nil, want error")
		}
	})
}

func TestIDConstructors_AcceptNonEmpty(t *testing.T) {
	cases := []struct {
		name  string
		check func() error
		want  string
	}{
		{
			name: "NewChainID",
			check: func() error {
				id, err := NewChainID("privilege_escalation_path")
				if err != nil || id.String() != "privilege_escalation_path" {
					return errFromCase(err, id.String(), "privilege_escalation_path")
				}
				return nil
			},
		},
		{
			name: "NewFindingID",
			check: func() error {
				id, err := NewFindingID("a1b2c3d4e5f6")
				if err != nil || id.String() != "a1b2c3d4e5f6" {
					return errFromCase(err, id.String(), "a1b2c3d4e5f6")
				}
				return nil
			},
		},
		{
			name: "NewIssueID",
			check: func() error {
				id, err := NewIssueID("issue-001")
				if err != nil || id.String() != "issue-001" {
					return errFromCase(err, id.String(), "issue-001")
				}
				return nil
			},
		},
		{
			name: "NewStatementID",
			check: func() error {
				id, err := NewStatementID("AllowReadOnly")
				if err != nil || id.String() != "AllowReadOnly" {
					return errFromCase(err, id.String(), "AllowReadOnly")
				}
				return nil
			},
		},
		{
			name: "NewGranteeID",
			check: func() error {
				id, err := NewGranteeID("http://acs.amazonaws.com/groups/global/AllUsers")
				if err != nil || id.String() != "http://acs.amazonaws.com/groups/global/AllUsers" {
					return errFromCase(err, id.String(), "http://acs.amazonaws.com/groups/global/AllUsers")
				}
				return nil
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type idMismatchError struct {
	got, want string
	wrapped   error
}

func (e idMismatchError) Error() string {
	if e.wrapped != nil {
		return e.wrapped.Error()
	}
	return "id mismatch: got " + e.got + ", want " + e.want
}

func errFromCase(err error, got, want string) error {
	if err != nil {
		return idMismatchError{wrapped: err}
	}
	return idMismatchError{got: got, want: want}
}
