; Rust tree-sitter queries for generic secret detection.
; Matches string literal assignments to variables.

; Let declaration
; let password = "secret_value";
(let_declaration
  pattern: (identifier) @name
  value: (string_literal (string_content) @value))

; Static/const item
; const PASSWORD: &str = "secret_value";
; static SECRET: &str = "secret_value";
(const_item
  name: (identifier) @name
  value: (string_literal (string_content) @value))

(static_item
  name: (identifier) @name
  value: (string_literal (string_content) @value))

; Assignment expression
; password = "secret_value";
(assignment_expression
  left: (identifier) @name
  right: (string_literal (string_content) @value))

; Field access assignment
; config.password = "secret_value";
(assignment_expression
  left: (field_expression
    field: (field_identifier) @name)
  right: (string_literal (string_content) @value))
