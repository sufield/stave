# Control Reference — MQ

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.MQ.ACTIVEMQ.EOL.001

**Amazon MQ ActiveMQ Version Must Not Be End-of-Life**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

Amazon MQ ActiveMQ brokers must not run engine versions that have reached end-of-life. ActiveMQ 5.15.x is past community support and no longer receives security patches. Message brokers handle authentication credentials, application events, and inter-service communication — an unpatched broker engine is a credential-bearing service running unmaintained code. AWS will eventually force-upgrade brokers on deprecated versions during a maintenance window the operator did not schedule.

**Remediation:** Upgrade the broker to ActiveMQ 5.17.x or later. Use aws mq update-broker --engine-version 5.17.6. Test message consumers and producers against the new version before upgrading production — major version upgrades may change protocol behavior or deprecate features.

---

### CTL.MQ.ENGINE.EOL.001

**Amazon MQ Engine Version Must Not Be End-of-Life**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

Amazon MQ brokers must not run engine versions that have reached end-of-life. RabbitMQ 3.8 and 3.9 reached EOL in 2023, and ActiveMQ 5.15 is past community support. AWS publishes version support timelines per engine; brokers on EOL versions no longer receive security patches from the engine vendor. Message brokers handle authentication credentials, application events, and inter-service communication — an unpatched broker engine is a credential-bearing service running unmaintained code. AWS will eventually force-upgrade brokers on deprecated versions during a maintenance window the operator did not schedule.

**Remediation:** Upgrade the broker to a supported engine version. For RabbitMQ, upgrade to 3.13.x. For ActiveMQ, upgrade to 5.17.x or later. Use aws mq update-broker --engine-version <ver>. Test message consumers and producers against the new version before upgrading production — major version upgrades may change protocol behavior or deprecate features.

---

### CTL.MQ.PUBLIC.001

**Amazon MQ Brokers Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Amazon MQ brokers must not expose public endpoints. Public brokers allow unauthenticated or internet-based access to message queues.

**Remediation:** Disable public accessibility on the broker.

---

