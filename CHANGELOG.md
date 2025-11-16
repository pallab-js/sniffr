# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SSL/TLS protocol parsing and display
- Hex dump output format
- Advanced packet filtering with AND/OR/NOT operators and parentheses
- IPv6 improvements including ICMPv6 support
- Comprehensive unit tests for packet filtering
- Performance optimizations for statistics collection

### Changed
- Enhanced filter parsing to support complex expressions
- Improved IPv6 header parsing
- Updated README with new features

### Fixed
- Hex dump display now shows actual packet data
- Filter parsing precedence issues
- IPv6 transport layer offset calculations