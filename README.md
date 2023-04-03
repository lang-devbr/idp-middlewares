# idp-middlewares

to publish golang module: https://go.dev/doc/modules/publishing#:~:text=versioning%20workflow.-,Publishing%20steps,-Use%20the%20following

export IDP_SECRET

1 - git tag v0.1.7

2 - git push origin v0.1.7

3 - GOPROXY=proxy.golang.org go list -m github.com/lang-devbr/idp-middlewares@v0.1.7
