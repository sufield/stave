; MICROVM-023 (Z3). facts define has_wildcard/is_microvm_admin. finding = wildcard AND not admin.
(assert has_wildcard)(assert (not is_microvm_admin))(check-sat)
