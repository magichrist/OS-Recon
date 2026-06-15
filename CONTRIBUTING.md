# Contributing
Thanks for your interest in OS-Recon. It's an early MVP so contributions, bug reports, and feedback are all welcome.

## Ways to help right now
- Test the scanner and report false positives (open an issue with the platform and what it returned)
- Test the nodriver deep pry layer - it's the most fragile part
- Suggest platforms to add to the social scanner

## Opening issues
Feel free to open your own issues. Prefix the title with the type of change - `feature`, `bug`, `refactor`, `docs`, etc. If the issue is larger in scope, add a short description of the problem and what a solution might look like.

Issues are labeled to signal what kind of contribution is expected:

| Label | Meaning |
|---|---|
| `small-issue` | A tight, self-contained task resolved by a single PR |
| `tracking-issue` | Ongoing task - multiple contributors can submit separate PRs |
| `mega-issue` | Codebase-wide sweep - accepts multiple scoped PRs |

If you're looking for somewhere to start, filter by `good first issue` or `small-issue`.

## Contributing code
1. Fork the repo
2. Create a branch (`git checkout -b feature/your-feature`)
3. Make sure your code works before opening a PR - don't commit broken or untested changes
4. Open a pull request

**PR descriptions matter.** Write your PR like an issue: what problem does it solve, what did you change, and why. If it touches multiple areas, break it down by section. This keeps review fast and makes the history readable.

For larger changes, open an issue first so we can discuss before you build it. See the README for setup instructions.

## AI Policy
Using AI tools while contributing is fine as long as you check and verify the code works. However, **automated AI agent PRs are not accepted** - no unsupervised bots opening pull requests or issues. Every contribution should have a human who wrote it, reviewed it, and stands behind it.
