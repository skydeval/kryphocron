# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

### Fixed

### Changed
- `InspectionNotification` shape change (Phase 1 → Phase 3) breaking for any prototype queue impls (#25)
- `FallbackAuditSink::record_panic` / `record_composite_failure` trait signatures gained `at: SystemTime` parameter (Phase 1 → Phase 3 breaking) (#24)
- `EVENT_SCHEMA_VERSION` type migration: Phase 1 `u32` → Phase 3 `SemVer` may break Phase 1 consumers (#23)
- `ModerationAuditEvent` variant names: kickoff says `ModeratorRead`/`ModeratorTakedown`; spec §6.5 commits `ModeratorInspected`/`ModeratorTookDown` (#20)
- `SyncPerspective` variant names: kickoff prose says `Sender`/`Receiver`; spec §6.3 commits `LocalAsSender`/`LocalAsReceiver` (#19)
- `kryphocron-lockfile-update` binary not shipped (kryphocron-lexicons#2)
- `proto-blue-codegen` library-API integration (kryphocron-lexicons#1)
- `ServiceIdentity` Hash interaction with rotation evidence (#14)
- Per-capability oracle query sets are Phase-1 interpretations (#6)
- proto-blue placeholder types in src/proto.rs (#3)
