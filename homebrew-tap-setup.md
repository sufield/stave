status : complete

# Homebrew Tap Setup

GoReleaser pushes a Homebrew formula to `sufield/homebrew-tap` on each release. This requires a one-time setup.

## 1. Create the Tap Repository

Create a public repository at `github.com/sufield/homebrew-tap` with a `Formula/` directory.

```bash
gh repo create sufield/homebrew-tap --public --description "Homebrew formulae for sufield tools"
git clone git@github.com:sufield/homebrew-tap.git
cd homebrew-tap
mkdir Formula
echo "# homebrew-tap" > README.md
git add . && git commit -m "Initial commit" && git push
```

## 2. Create a Personal Access Token

GoReleaser needs a PAT to push formula updates to the tap repository (the default `GITHUB_TOKEN` cannot push to other repos).

1. Go to **Settings > Developer settings > Personal access tokens > Fine-grained tokens**.
2. Create a token with:
   - **Repository access**: Only select `sufield/homebrew-tap`.
   - **Permissions**: Contents (Read and write).
3. Copy the token.

## 3. Add the Secret

Add the token as a repository secret on `sufield/stave`:

```bash
gh secret set TAP_GITHUB_TOKEN --repo sufield/stave
```

Paste the token when prompted.

## 4. Verify

After the next release, users can install via:

```bash
brew tap sufield/tap
brew install stave
```
