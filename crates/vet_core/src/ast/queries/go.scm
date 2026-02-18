; Go tree-sitter queries for generic secret detection.
; Matches string literal assignments to variables.

; Short variable declaration
; password := "secret_value"
(short_var_declaration
  left: (expression_list
    (identifier) @name)
  right: (expression_list
    (interpreted_string_literal) @value))

; Variable declaration with var keyword
; var password = "secret_value"
(var_declaration
  (var_spec
    name: (identifier) @name
    value: (expression_list
      (interpreted_string_literal) @value)))

; Const declaration
; const password = "secret_value"
(const_declaration
  (const_spec
    name: (identifier) @name
    value: (expression_list
      (interpreted_string_literal) @value)))

; Assignment expression
; password = "secret_value"
(assignment_statement
  left: (expression_list
    (identifier) @name)
  right: (expression_list
    (interpreted_string_literal) @value))

; Composite literal key-value pair
; map[string]string{"password": "secret_value"}
(keyed_element
  (literal_element
    (interpreted_string_literal) @name)
  (literal_element
    (interpreted_string_literal) @value))
