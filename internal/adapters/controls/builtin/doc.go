// Package builtin loads embedded control definitions that ship with the Stave
// binary.
//
// Control YAML files are copied from controls/ into internal/controldata/embedded/
// at build time (via make sync-controls) and loaded at runtime from the
// controldata package. [Registry.All] returns every built-in control; [Registry.Filtered]
// accepts a [Selector] to narrow by scope tags or severity.
package builtin
