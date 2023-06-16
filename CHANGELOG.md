Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[Unreleased]
------------

### Added

### Changed

### Fixed

### Removed

[0.6.0] - 2023-06-16
--------------------

### Added

- Added `Client::resume_session` method.
- Added `Client::serialize_session` method.
- Added `Client::fetch_protected_nodes` method.

### Changed

- Added `#[non_exhaustive]` attribute on `Error` enum.
- Changed `Error` variants from tuples to named fields.
- Changed `Client` to implement the `Send` and `Sync` traits.
- Changed `ClientBuilder::timeout` method to take an `Option<Duration>` instead of just `Duration`.
- Upgraded dependencies

### Fixed

### Removed

- Removed `Error::Pbkdf2Error` enum variant.

[0.5.0] - 2023-06-08
--------------------

### Added

- Added `Node::owner` getter method.
- Added `Node::modified_at` getter method.
- Added `Node::aes_key` getter method.
- Added `Node::aes_iv` getter method.
- Added `Node::condensed_mac` getter method.
- Added `Node::sparse_checksum` getter method.
- Added `compute_sparse_checksum` standalone function.
- Added `compute_condensed_mac` standalone function.
- Added `LastModified` enum.
- Added `Event` enum.
- Added `EventBatch` struct.
- Added `EventNode` struct.
- Added `EventNodeAttributes` struct.
- Added `Client::poll_event` method.
- Added `Client::wait_event` method.
- Added `Nodes::apply_events` method.

### Changed

- Renamed `Node::hash` to `Node::handle`.
- Renamed `Nodes::get_node_by_hash` to `Nodes::get_node_by_handle`.
- Renamed `Client::create_dir` to `Client::create_folder`.
- Changed `mega::Result<T>` to `mega::Result<T, E = mega::Error>`.
- Changed `Node::created_at` to return an owned `DateTime<Utc>` instead of borrowing.
- Changed `Client::upload_node` to now accept a last modification date (using `LastModified`).

### Fixed

- Resolved issues when decrypting attributes for shared nodes.
- Fixed handling of folder keys.
- Fixed folder key generation in `Client::create_folder`.
- Fixed last modification dates being overwritten when renaming nodes.

### Removed

- Removed `Clone` impl for `Node`.
- Removed `Nodes::iter_mut` method.

[0.4.1] - 2023-05-25
--------------------

### Fixed

- Fixed occasional `MALFORMED_ATTRIBUTES` issue due to incorrect attributes buffer padding.

[0.4.0] - 2023-04-12
--------------------

### Added

- Added `Client::{download_thumbnail, download_preview_image}`.
- Added `Client::{upload_thumbnail, upload_preview_image}`.
- Added `Node::{has_thumbnail, has_preview_image}`.
- Implemented `Default` trait for `ClientBuilder`.
- Added `NodeKind::{is_file, is_folder, is_root, is_rubbish_bin, is_inbox}`.

### Changed

- Changed `Error` to implement both `Send` and `Sync`.
- Slightly simplified `HttpClient` trait.

### Fixed

- Fixed issue with incorrect MAC computation.
- Added appropriate size limits on I/O readers and writers.

### Removed

- Removed `Client::move_to_rubbish_bin` function.

[0.3.0] - 2023-04-09
--------------------

### Added

- Added HTTPS usage (during downloads and uploads) as a configurable option.
- Added support for listing and downloading from public MEGA links.
- Added `Nodes` type to represent collections of fetched nodes.
- Exported `NodeKind` type.

### Changed

- Most `Client` functions can now be called concurrently.

### Fixed

- Fixed issues with MAC computation when uploading files.

[0.2.1] - 2023-04-02
--------------------

### Added

- Added `Client::move_to_rubbish_bin` function.

### Fixed

- Fixed an issue where errors could be encountered after some successful operations, like moving or renaming a node.

[0.2.0] - 2023-02-26
--------------------

### Added

- Initial library release.

[0.1.0] - 2017-06-30 [YANKED]
-----------------------------

Legacy yanked release.
