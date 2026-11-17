# ForceDuo inside LiveContainer

This checkout adds experimental compatibility with the iOS [LiveContainer](https://github.com/LiveContainer/LiveContainer) app launcher. It is not a Docker image. Device functionality has not been verified; an IPA launching successfully does not establish that database access or patching works.

## Changes

ForceDuo detects LiveContainer's `LC_HOME_PATH` and dynamically asks `LCSharedUtils.appGroupID` for the host's real App Group. Guest App Groups are virtual folders and cannot be used for the underlying system container query. If no real host group is available, database access stops with an error. Native launches use upstream's entitlement-based group resolution, including group IDs rewritten by a signer.

The access helper renames the existing App Group cache aside rather than deleting it, then restores it after the query, including failed queries. This matters because the host group can contain LiveContainer or SideStore data. Force quitting during the query can still interrupt restoration: with ForceDuo stopped, preserve any `Library/Caches.ForceDuo-<UUID>` directory and restore it to `Library/Caches` only after checking for newly created cache contents. Do not delete backups or run another copy concurrently.

The implementation follows LiveContainer's [guest file-manager hook](https://github.com/LiveContainer/LiveContainer/blob/main/LiveContainer/Tweaks/NSFileManager%2BGuestHooks.m) and [host group resolver](https://github.com/LiveContainer/LiveContainer/blob/main/LiveContainer/LCSharedUtils.m).

## Build and import

On a Mac with Xcode and an iOS 27 SDK, run:

```sh
./scripts/build-livecontainer.sh
```

Import `dist/ForceDuo-LiveContainer.ipa` with LiveContainer's plus button. The IPA is unsigned for LiveContainer to process with its own signing setup. Run ForceDuo alone, without another ForceDuo guest or native instance. If diagnostic file selection does not work, enable LiveContainer's per-app “Fix File Picker” option.

The upstream project targets iOS 27.0 and understands only its explicitly listed LaunchServices record layouts. This change does not add support for other database layouts or repair the underlying `worse_query` vulnerability on patched OS versions. A host without a real App Group cannot provide the required access.

## Required device verification

Before considering this usable on a particular device:

1. Confirm the app launches and its `App Groups entitled` diagnostic reports the real host access group after `using`.
2. Load the installed-app list and export diagnostics. Confirm the database layout is recognized.
3. Confirm the original host cache and its contents are restored after successful and failed access attempts.
4. On a backed-up test device, enable one legacy app, relaunch it, and verify the intended UI change.
5. Revert that app and verify both its original SDK value and UI behavior return.
6. Restart LiveContainer and confirm selections, backups, and diagnostic exports persist.

No macOS toolchain or connected test iPhone was available in the Linux workspace used to prepare these changes. Neither compilation nor these device checks have been completed.

## Build with GitHub Actions

The **Build LiveContainer IPA** workflow builds on GitHub's `xcode-27` Mac runner using the same script as the local build. It runs automatically when app, build script, or workflow changes are pushed to `main`, and for pull requests. You can also start it manually:

1. Push the workflow to your fork's `main` branch.
2. Open the repository's **Actions** tab. If workflows are disabled for the fork, enable them.
3. Select **Build LiveContainer IPA**, then **Run workflow** on `main`.
4. Open the successful run and download **ForceDuo-LiveContainer-<run number>** under **Artifacts**.
5. Extract the downloaded ZIP and import the IPA into LiveContainer.

No signing certificates, Apple developer credentials, or repository secrets are required. Artifacts are retained for 30 days. The workflow checks the selected SDK, builds the app, and checks ZIP integrity; it does not run an iPhone compatibility test.

## Automatic releases

After a successful build on `main` (push or manual run), a separate job publishes a GitHub Release with `ForceDuo-LiveContainer.ipa` attached directly. Pull request builds and manual runs on other branches do not publish releases. The release is marked as latest and tagged `build-<run number>-<attempt>` at the exact commit that was built. Reruns get a new tag rather than replacing an existing release.

Download the IPA directly from the repository's **Releases** page; no artifact ZIP extraction is needed. Releases remain available until deleted, independently of the 30-day Actions artifact retention. Publishing uses the built-in `GITHUB_TOKEN`, with write access limited to the release job, so no personal token is needed. Repository or organization policies must allow workflow tokens to write repository contents.
