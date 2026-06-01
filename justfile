# HpuSim development utilities — run `just` to list all commands.
#
# Key workflows:
#   just ci             Full check suite (fmt + lint + test)
#   just git-hook-init  Install git hooks delegating to these commands
#
# Context-aware scope: invoke from the workspace root to target all crates,
# or from any crate directory to target that package only.

# ── Scope detection ───────────────────────────────────────────────────────────
# `invocation_directory()` is where the user ran `just` from.
# `justfile_directory()` is always the workspace root (where this file lives).
# When they differ, derive the package name from the invocation directory name.

CARGO_SCOPE := if invocation_directory() == justfile_directory() {
    "--workspace"
} else {
    "-p " + file_name(invocation_directory())
}

FMT_SCOPE := if invocation_directory() == justfile_directory() {
    "--all"
} else {
    "-p " + file_name(invocation_directory())
}

# ── Default ──────────────────────────────────────────────────────────────────

# List available commands
default:
    @just --list

# ── Format ────────────────────────────────────────────────────────────────────

# Check formatting (scoped to current context)
fmt-check:
    cargo fmt {{FMT_SCOPE}} -- --check

# Apply formatting (scoped to current context)
fmt:
    cargo fmt {{FMT_SCOPE}}

# ── Lint ──────────────────────────────────────────────────────────────────────

# Lint (warnings become errors, dependencies excluded)
clippy:
    cargo clippy {{CARGO_SCOPE}} --all-targets --no-deps -- -D warnings

# Lint and auto-apply safe fixes
clippy-fix:
    cargo clippy {{CARGO_SCOPE}} --all-targets --fix --allow-dirty --no-deps -- -D warnings

# ── Check & Build ─────────────────────────────────────────────────────────────

# Type-check without producing binaries
check:
    cargo check {{CARGO_SCOPE}} --all-targets

# Build (dev profile)
build:
    cargo build {{CARGO_SCOPE}}

# Build with the devo profile (opt-level 3, debug-assertions off)
build-devo:
    cargo build {{CARGO_SCOPE}} --profile devo

# Build release
build-release:
    cargo build {{CARGO_SCOPE}} --release

# ── Test ──────────────────────────────────────────────────────────────────────

# Run the test suite
test:
    cargo test {{CARGO_SCOPE}} --all-targets

# ── Documentation ─────────────────────────────────────────────────────────────

# Build and open documentation (dependencies excluded)
doc:
    cargo doc {{CARGO_SCOPE}} --no-deps --open

# ── Publish ───────────────────────────────────────────────────────────────────

# Dry-run publish check
publish-check:
    cargo publish --dry-run --allow-dirty {{CARGO_SCOPE}}

# ── CI ────────────────────────────────────────────────────────────────────────

# Full check suite: format → lint → test
ci: fmt-check clippy test

# ── Git hooks ─────────────────────────────────────────────────────────────────
# List of supported git hook
# supported-git-hooks := "['commit-msg', 'pre-commit', 'pre-merge-commit', 'prepare-commit-msg', 'pre-push', 'pre-rebase']"
supported-git-hooks := "['pre-commit', 'pre-push']"

# Fast pre-commit gate: format check only
pre-commit: fmt-check

# Full CI gate before push
pre-push: ci

pre-rebase:

# Install git hooks — each hook delegates to its matching `just <name>` recipe
git-hook-init:
    #!/usr/bin/env python3
    from pathlib import Path
    import os
    print("+Init git hooks")
    git_hook_path = Path.cwd() / '.git' / 'hooks'
    git_hook_path.mkdir(parents=True, exist_ok=True)
    for hook_name in {{supported-git-hooks}}:
        hook_file = git_hook_path / hook_name
        if hook_file.exists():
            print(f"Hook '{hook_name}' already exists")
            answer = None
            while answer not in ('y', 'yes', 'n', 'no'):
                answer = input("Overwrite? [y/n/d(isplay)] ").strip().lower()
                if answer in ('d', 'display'):
                    print(hook_file.read_text())
                    answer = None
            if answer in ('n', 'no'):
                print(f"Skipped '{hook_name}'")
                continue
        hook_file.write_text(
            "#!/usr/bin/env sh\n"
            "# Delegates to the matching `just` recipe.\n"
            "set -e\n"
            f"just {hook_name}\n"
        )
        os.chmod(hook_file, 0o744)
        print(f"Installed '{hook_name}'")
