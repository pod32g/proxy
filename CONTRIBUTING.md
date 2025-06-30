# Contributing

Thank you for considering a contribution! All pull requests trigger the **Test**
GitHub Actions workflow which runs `go test ./...`.

To keep the `main` branch healthy, configure a branch protection rule that
requires this workflow to pass before merging. You can run the tests locally with:

```sh
go test ./...
```

