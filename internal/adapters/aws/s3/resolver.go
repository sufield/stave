package s3

import (
	"strings"

	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

type trieNode struct {
	children map[byte]*trieNode
	perm     risk.Permission
	terminal bool
}

// Resolver maps S3 action strings to Permission bits using a trie
// for O(L) longest-prefix-match lookup.
type Resolver struct {
	root *trieNode
}

// NewResolver constructs a Resolver pre-loaded with S3 action mappings.
func NewResolver() *Resolver {
	r := &Resolver{root: &trieNode{children: make(map[byte]*trieNode)}}
	// Exact matches
	r.insert("*", risk.PermFullControl)
	r.insert("s3:*", risk.PermFullControl)
	r.insert("s3:getobject", risk.PermRead)
	r.insert("s3:putobject", risk.PermWrite)
	r.insert("s3:listbucket", risk.PermList)
	r.insert("s3:getbucketacl", risk.PermAdminRead)
	r.insert("s3:getobjectacl", risk.PermAdminRead)
	r.insert("s3:putbucketacl", risk.PermAdminWrite)
	r.insert("s3:putobjectacl", risk.PermAdminWrite)
	r.insert("s3:deleteobject", risk.PermDelete)
	r.insert("s3:deletebucket", risk.PermDelete)
	r.insert("s3:listbucketversions", risk.PermList)
	// Prefix catch-alls (longest-prefix-match means exact entries above win).
	// s3:get* and s3:list* mirror the existing put/delete catch-alls so
	// novel actions added by AWS (s3:GetObjectVersionTagging, s3:ListMultipartUploadParts,
	// etc.) are classified by intent rather than reported as unknown.
	r.insert("s3:get", risk.PermRead)
	r.insert("s3:list", risk.PermList)
	r.insert("s3:put", risk.PermWrite)
	r.insert("s3:delete", risk.PermDelete)
	return r
}

// Resolve returns the Permission for an action using longest-prefix-match.
// O(L) where L is the length of the action string.
// AWS action names are case-insensitive — input is normalized to lowercase.
// The second return is true when the trie matched at least one terminal
// node (an action this resolver knows about) and false when the action
// is unrecognized.
func (r *Resolver) Resolve(action string) (risk.Permission, bool) {
	action = strings.ToLower(action)
	node := r.root
	var lastMatch risk.Permission
	matched := false
	for i := 0; i < len(action); i++ {
		child, ok := node.children[action[i]]
		if !ok {
			break
		}
		node = child
		if node.terminal {
			lastMatch = node.perm
			matched = true
		}
	}
	return lastMatch, matched
}

func (r *Resolver) insert(key string, perm risk.Permission) {
	node := r.root
	for i := 0; i < len(key); i++ {
		child, ok := node.children[key[i]]
		if !ok {
			child = &trieNode{children: make(map[byte]*trieNode)}
			node.children[key[i]] = child
		}
		node = child
	}
	node.terminal = true
	node.perm = perm
}

// ARN returns the full S3 ARN for a bucket: "arn:aws:s3:::<name>".
func ARN(ref kernel.BucketRef) string {
	return "arn:aws:s3:::" + ref.Name()
}
