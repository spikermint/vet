; Ruby tree-sitter queries for generic secret detection.
; Matches string literal assignments to variables.

; Simple variable assignment
; password = "secret_value"
(assignment
  left: (identifier) @name
  right: (string (string_content) @value))

; Instance variable assignment
; @password = "secret_value"
(assignment
  left: (instance_variable) @name
  right: (string (string_content) @value))

; Hash literal pair / keyword argument with symbol key
; { password: "secret_value" }
; connect(password: "secret_value")
; Ruby uses the same node type for both hash pairs and keyword arguments.
(pair
  key: (hash_key_symbol) @name
  value: (string (string_content) @value))

; Hash literal pair with string key
; { "password" => "secret_value" }
(pair
  key: (string (string_content) @name)
  value: (string (string_content) @value))
