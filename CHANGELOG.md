# Changelog

## [Unreleased]

### Added
- Added implementation details for three opcodes:
  - `NOP`: Added implementation from stackops.cpp (line 537)
  - `XCHG_0I` (SWAP): Added implementation from stackops.cpp (line 538)
  - `PUSH`: Added implementation from contops.cpp (line 1027)

### Changed
- Updated schema.json to include implementation field with the following structure:
  ```json
  "implementation": {
    "file": "string",
    "line": "integer",
    "handler": "string",
    "declaration": "string",
    "args": "array",
    "body": "string"
  }
  ```

### Technical Details
- Implementation field includes:
  - Source file location
  - Line number
  - Handler function name
  - Declaration code
  - Function arguments
  - Implementation body 