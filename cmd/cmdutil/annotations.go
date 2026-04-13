// Package cmdutil provides shared CLI utilities for Stave commands.
package cmdutil

// AnnotationConfigOptional marks a command that can operate without
// valid project configuration. Bootstrap skips the config health check
// for these commands. Set in the command's Annotations map:
//
//	Annotations: map[string]string{cmdutil.AnnotationConfigOptional: "true"}
const AnnotationConfigOptional = "stave:config-optional"
