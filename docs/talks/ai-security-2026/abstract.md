# Your AI Agent Has Admin Access. Your Scanner Says You're Compliant.

84% of organizations run AI workloads in the cloud. Their security
scanners check encryption, VPC isolation, and model access lists —
component-level settings that all pass. None check whether the AI
agent's execution role can invoke any Lambda function in the
account, or whether those Lambda functions can reach S3 buckets
containing Protected Health Information.

This talk demonstrates compound risk detection on the AI surface:
how five individually passing security checks compose into three
CRITICAL attack paths when a Bedrock agent, its Lambda tools, and
an S3 bucket containing PHI are analyzed together. Using an
open-source tool that exports configuration facts to nine
independent reasoning engines — including SMT solvers used to
verify flight software — we prove the attack path exists
mathematically, quantify the attacker's cost, and show the
remediation (zero dollars plus $0.050 per million active users)
with formal verification that the path is eliminated.

Live demo included. Runs on a static snapshot with no cloud
credentials.

**Audience:** Cloud security engineers, platform teams, CISOs
evaluating AI governance tooling.

**Takeaway:** Your scanner checks components. Your AI agent's
risk is in the interactions between components. This talk shows
you what compound detection finds that component scanning misses.
