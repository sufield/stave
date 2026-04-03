package compliance

import "testing"

func TestPolicyStatement_HasSignatureAgeGuardrail(t *testing.T) {
	tests := []struct {
		name string
		stmt PolicyStatement
		want bool
	}{
		{
			name: "Deny with NumericGreaterThan s3:signatureAge — true",
			stmt: func() PolicyStatement {
				stmts, _ := ParsePolicyStatements(`{
					"Statement": [{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:*",
						"Resource": "*",
						"Condition": {
							"NumericGreaterThan": {
								"s3:signatureAge": 600000
							}
						}
					}]
				}`)
				return stmts[0]
			}(),
			want: true,
		},
		{
			name: "Allow with NumericGreaterThan s3:signatureAge — false (not a Deny)",
			stmt: func() PolicyStatement {
				stmts, _ := ParsePolicyStatements(`{
					"Statement": [{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:*",
						"Resource": "*",
						"Condition": {
							"NumericGreaterThan": {
								"s3:signatureAge": 600000
							}
						}
					}]
				}`)
				return stmts[0]
			}(),
			want: false,
		},
		{
			name: "Deny but no condition — false",
			stmt: func() PolicyStatement {
				stmts, _ := ParsePolicyStatements(`{
					"Statement": [{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:*",
						"Resource": "*"
					}]
				}`)
				return stmts[0]
			}(),
			want: false,
		},
		{
			name: "Deny with wrong condition key — false",
			stmt: func() PolicyStatement {
				stmts, _ := ParsePolicyStatements(`{
					"Statement": [{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:*",
						"Resource": "*",
						"Condition": {
							"NumericGreaterThan": {
								"s3:TlsVersion": 1.2
							}
						}
					}]
				}`)
				return stmts[0]
			}(),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.stmt.HasSignatureAgeGuardrail(); got != tc.want {
				t.Errorf("HasSignatureAgeGuardrail() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPolicyStatement_HasAuthTypeGuardrail(t *testing.T) {
	tests := []struct {
		name string
		stmt PolicyStatement
		want bool
	}{
		{
			name: "Deny with StringNotEquals s3:authType REST-HEADER — true",
			stmt: func() PolicyStatement {
				stmts, _ := ParsePolicyStatements(`{
					"Statement": [{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "*",
						"Condition": {
							"StringNotEquals": {
								"s3:authType": "REST-HEADER"
							}
						}
					}]
				}`)
				return stmts[0]
			}(),
			want: true,
		},
		{
			name: "Allow with StringNotEquals s3:authType REST-HEADER — false (not a Deny)",
			stmt: func() PolicyStatement {
				stmts, _ := ParsePolicyStatements(`{
					"Statement": [{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "*",
						"Condition": {
							"StringNotEquals": {
								"s3:authType": "REST-HEADER"
							}
						}
					}]
				}`)
				return stmts[0]
			}(),
			want: false,
		},
		{
			name: "Deny but wrong authType value — false",
			stmt: func() PolicyStatement {
				stmts, _ := ParsePolicyStatements(`{
					"Statement": [{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "*",
						"Condition": {
							"StringNotEquals": {
								"s3:authType": "REST-QUERY-STRING"
							}
						}
					}]
				}`)
				return stmts[0]
			}(),
			want: false,
		},
		{
			name: "Deny with no condition — false",
			stmt: func() PolicyStatement {
				stmts, _ := ParsePolicyStatements(`{
					"Statement": [{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "*"
					}]
				}`)
				return stmts[0]
			}(),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.stmt.HasAuthTypeGuardrail(); got != tc.want {
				t.Errorf("HasAuthTypeGuardrail() = %v, want %v", got, tc.want)
			}
		})
	}
}
