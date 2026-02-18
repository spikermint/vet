; TypeScript tree-sitter queries for generic secret detection.
; Shares most structure with JavaScript.

; Variable declaration
; const password: string = "secret_value"
; let apiKey = "secret_value"
(variable_declarator
  name: (identifier) @name
  value: (string (string_fragment) @value))

; Property assignment via member expression
; config.password = "secret_value"
(assignment_expression
  left: (member_expression
    property: (property_identifier) @name)
  right: (string (string_fragment) @value))

; Simple assignment
; password = "secret_value"
(assignment_expression
  left: (identifier) @name
  right: (string (string_fragment) @value))

; Object literal property
; { password: "secret_value" }
(pair
  key: (property_identifier) @name
  value: (string (string_fragment) @value))

; Object literal with string key
; { "password": "secret_value" }
(pair
  key: (string (string_fragment) @name)
  value: (string (string_fragment) @value))
