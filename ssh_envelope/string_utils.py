# ```swift
# public extension Sequence where Element == String? {
#     func compactJoined(separator: String = "") -> String {
#         self.compactMap { $0 }.joined(separator: separator)
#     }
# }
# ```

def compact_joined(self, separator: str = "") -> str:
    return separator.join(filter(None, self))

# ```swift
# public extension KeyValuePairs where Key == String, Value == String? {
#     func compactJoined(separator: String = "") -> String {
#         self.map { (key, value) in
#             if let value {
#                 "\(key): \(value)"
#             } else {
#                 nil
#             }
#         }
#         .compactJoined(separator: separator)
#     }
# }
# ```

def compact_joined_key_values(self, separator: str = "") -> str:
    return separator.join(f"{key}: {value}" for key, value in self if value is not None)

# ```swift
# public extension KeyValuePairs where Key == String, Value == String {
#     func joined(separator: String = "") -> String {
#         self.map { (key, value) in
#             "\(key): \(value)"
#         }
#         .joined(separator: separator)
#     }
# }
# ```

def joined_key_values(self, separator: str = "") -> str:
    return separator.join(f"{key}: {value}" for key, value in self)
