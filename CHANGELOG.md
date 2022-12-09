<!--
Guiding Principles:

Changelogs are for humans, not machines.
There should be an entry for every single version.
The same types of changes should be grouped.
Versions and sections should be linkable.
The latest version comes first.
The release date of each version is displayed.
Mention whether you follow Semantic Versioning.

Usage:

Change log entries are to be added to the Unreleased section under the
appropriate stanza (see below). Each entry should ideally include a tag and
the Github issue reference in the following format:

* (<tag>) \#<issue-number> message

The issue numbers will later be link-ified during the release process so you do
not have to worry about including a link manually, but you can if you wish.

Types of changes (Stanzas):

"Features" for new features.
"Improvements" for changes in existing functionality.
"Deprecated" for soon-to-be removed features.
"Bug Fixes" for any bug fixes.
"Client Breaking" for breaking CLI commands and REST routes used by end-users.
"API Breaking" for breaking exported APIs used by developers building on SDK.
"State Machine Breaking" for any changes that result in a different AppState given same genesisState and txList.

Ref: https://keepachangelog.com/en/1.0.0/
-->

# Changelog

## Unreleased

## [v0.2.1] - 2022-12-09
- (core) [\#13](https://github.com/evmos/evmos-ledger-go/pull/13) Fix panic on Ledger derivation failure

## [v0.2.0] - 2022-12-08

### Improvements

- (ci) [\#9](https://github.com/evmos/evmos-ledger-go/pull/9) Add workflows and setup files
- (deps) [\#11](https://github.com/evmos/evmos-ledger-go/pull/11) Bump technote-space/get-diff-action from 6.1.1 to 6.1.2
- (core) [\#8](https://github.com/evmos/evmos-ledger-go/pull/8) Deprecate ethereum-ledger-go components

