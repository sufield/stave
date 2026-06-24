; MICROVM-022 (Z3). facts define is_production/exec_role/build_role. finding = prod AND (no exec OR no build).
(assert is_production)(assert (or (not exec_role) (not build_role)))(check-sat)
