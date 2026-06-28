<!-- managed:linked-repos -->
## Linked Repositories
- reechedlimit/BLHI
<!-- /managed:linked-repos -->

# BLHI Code Workflow

## Branch Strategy
- `main` — production branch. Always deployable.
- Feature branches — created for each task (name: `feature/short-description`)

## Process
1. Members create feature branches off `main`
2. Members push code and create pull requests
3. Team lead reviews and merges PRs using `gh pr merge`
4. After merge, Vercel auto-deploys to production

## Repository
- `reechedlimit/BLHI` — single repo containing:
  - `/website/` — Main BLHI site (static)
  - `/genealogy-tool/` — Flask app
  - `/outreach/` — Strategy documents