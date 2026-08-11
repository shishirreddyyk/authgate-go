# Push checklist

```bash
cd authgate-go

# 1. Verify locally (should be all green, no services needed)
go vet ./...
test -z "$(gofmt -l .)" && echo "gofmt clean"
go test ./... -race -count=1

# 2. Measure on your own hardware - these are the numbers you can quote
go run ./cmd/authgate &          # or: AUTHGATE_LIMIT=1000000 go run ./cmd/authgate &
go run ./cmd/loadtest -url http://localhost:8080/v1/echo \
  -token ag_demo_demo-secret -n 20000 -c 50
# paste the output back to me and I will put the real number on the resume
kill %1

# 3. Push
git init
git add .
git commit -m "authgate-go: API key auth, scopes, sliding-window rate limiting, abuse penalty box"
git branch -M main
gh repo create shishirreddyyk/authgate-go --public --source=. --remote=origin --push
# no gh? create the empty repo at github.com/new (public, no README), then:
#   git remote add origin https://github.com/shishirreddyyk/authgate-go.git
#   git push -u origin main

# 4. Confirm the Actions tab is green, then tell me
```

Nothing goes on the resume until step 4 passes.
