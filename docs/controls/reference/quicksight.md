# Control Reference — QUICKSIGHT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.QUICKSIGHT.DATASOURCE.ENCRYPT.001

**QuickSight Data Source Must Not Disable SSL**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

QuickSight data source has SSL disabled for the connection to the underlying data store. With SSL disabled, query traffic and result sets travel unencrypted between QuickSight and the data source.

**Remediation:** Update the data source to enable SSL. For Athena data sources, SSL is managed by the Athena service. For RDS/Redshift data sources, enable SSL in the connection parameters.

---

### CTL.QUICKSIGHT.DATASOURCE.VPC.001

**QuickSight Data Source Must Use VPC Connection**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

QuickSight data source connects to the underlying data store (Athena, RDS, Redshift) over the public network instead of through a VPC connection. Without a VPC connection, query traffic between QuickSight and the data store traverses the public AWS network. For Athena data sources this means QuickSight queries — which may return sensitive data — are not scoped to VPC network controls.

**Remediation:** Create a VPC connection in QuickSight and update the data source to use it. The VPC connection must have subnets and security groups that allow access to the underlying data store.

---

