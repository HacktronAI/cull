MAX_IMAGE_WORKERS = 4
MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
DOCKER_PULL_TIMEOUT_S = 300

LOCK_FILES = frozenset({
    "pnpm-lock.yaml",
    "package-lock.json",
    "yarn.lock",
    "bun.lock",
})

SKIP_DIRS = frozenset({
    ".git", ".svn", "__pycache__",
    ".next", ".nuxt", ".output",
    "dist", ".cache", ".turbo",
})

SKIP_IMAGE_ENTRIES = frozenset({
    "manifest.json", "index.json", "oci-layout", "repositories",
})
