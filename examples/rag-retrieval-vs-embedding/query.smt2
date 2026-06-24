; RAG-003 — retrieval role broader than embedding role (Z3 / SMT).
; Append after a generated facts.smt2 (closed-world define-fun for
; retrieval_perm / embedding_perm / write_action). Independent cross-check.
;
;   cat facts.smt2 query.smt2 | z3 -in
;   SAT + witness -> retrieval IS broader/has-write (FAIL).  UNSAT -> strict subset (PASS).
;
; Finds a single permission held by retrieval that is either (a) not held by
; embedding and not the design-intended bedrock:Retrieve, or (b) a write action.
; Sound: relations are total define-fun's, so Z3 cannot invent a permission.

(declare-const svc String)
(declare-const act String)
(declare-const res String)

(assert (retrieval_perm svc act res))
(assert (or
  (and (not (embedding_perm svc act res)) (not (= svc "bedrock")))  ; broader than embedding
  (write_action act)))                                              ; or holds a write action
(check-sat)
(get-value (svc act res))
