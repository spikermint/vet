; Java tree-sitter queries for generic secret detection.
; Matches string literal assignments to variables.

; Local variable declaration
; String password = "secret_value";
(local_variable_declaration
  declarator: (variable_declarator
    name: (identifier) @name
    value: (string_literal (string_fragment) @value)))

; Field declaration (class member)
; private String password = "secret_value";
(field_declaration
  declarator: (variable_declarator
    name: (identifier) @name
    value: (string_literal (string_fragment) @value)))

; Assignment expression
; password = "secret_value";
(assignment_expression
  left: (identifier) @name
  right: (string_literal (string_fragment) @value))

; Field access assignment
; config.password = "secret_value";
(assignment_expression
  left: (field_access
    field: (identifier) @name)
  right: (string_literal (string_fragment) @value))
