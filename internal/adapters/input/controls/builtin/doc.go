// Package builtin loads embedded control definitions that ship with the Stave
// binary.
//
// Control YAML files are copied from controls/ into this package's embedded/
// directory at build time (via make sync-controls) and loaded at runtime using
// [go:embed]. [LoadAll] returns every built-in control; [LoadFiltered] accepts a
// [Selector] to narrow by class, pack, or other criteria.
package builtin
