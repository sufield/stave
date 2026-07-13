// Package cmdutil provides shared CLI utilities for Stave commands.
package cmdutil

// AnnotationConfigOptional marks a command that can operate without
// valid project configuration. Bootstrap skips the config health check
// for these commands. Set in the command's Annotations map:
//
//	Annotations: map[string]string{cmdutil.AnnotationConfigOptional: "true"}
const AnnotationConfigOptional = "stave:config-optional"

// AnnotationDevOnly marks a command (and, by ancestry, its subcommands) as a
// developer-workflow command that must not run against production — e.g.
// project scaffolding (`generate`) or control authoring (`forge`). The
// bootstrap production guard rejects these when a production environment is
// detected. The commands are not destructive; they simply have no place in
// production. Set in the command's Annotations map:
//
//	Annotations: map[string]string{cmdutil.AnnotationDevOnly: "true"}
const AnnotationDevOnly = "stave:dev-only"

// AnnotationSanitizeAware marks a command that actually implements
// --sanitize behavior. Commands without this annotation reject the
// flag with exit 2 so operators don't get a false sense of redaction.
const AnnotationSanitizeAware = "stave:sanitize-aware"
