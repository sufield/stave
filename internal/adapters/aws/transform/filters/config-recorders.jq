# aws configservice describe-configuration-recorders  ->  one aws_config_recorder
# asset per recorder. Single-call source. The obs id is normalized to
# arn:aws:config:<region>:<account>:config-recorder/<name> (region parsed from
# the recorder's own arn; the raw arn is the longer
# configuration-recorder/<name>/<id> form).
#
# records_all_resources is computed: a recorder only records ALL resources when
# it records all supported types AND includes the global (account-level) ones.
.ConfigurationRecorders[] | {
  id: ("arn:aws:config:" + (.arn | split(":")[3]) + ":" + $account + ":config-recorder/" + .name),
  type: "aws_config_recorder",
  vendor: "aws",
  properties: { compliance: {
    kind: "config_recorder",
    config: {
      records_all_resources: ((.recordingGroup.allSupported == true)
        and (.recordingGroup.includeGlobalResourceTypes == true))
    }
  } }
}
