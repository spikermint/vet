; Python tree-sitter queries for generic secret detection.
; Matches string literal assignments to variables.

; Simple variable assignment
; password = "secret_value"
(assignment
  left: (identifier) @name
  right: (string (string_content) @value))

; Object/attribute property assignment
; config.password = "secret_value"
; self.api_key = "secret_value"
(assignment
  left: (attribute
    attribute: (identifier) @name)
  right: (string (string_content) @value))

; Dictionary literal
; {"password": "secret_value"}
(dictionary
  (pair
    key: (string (string_content) @name)
    value: (string (string_content) @value)))

; Named/keyword argument
; connect(password="secret_value")
(keyword_argument
  name: (identifier) @name
  value: (string (string_content) @value))
