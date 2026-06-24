; MICROVM-021 (Z3). facts define shell_ingress/is_production. finding = both.
(assert shell_ingress)(assert is_production)(check-sat)
