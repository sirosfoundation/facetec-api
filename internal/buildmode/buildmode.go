// Package buildmode reports whether this binary was built for production.
//
// It exists for one purpose: a few configuration choices are reasonable on a
// development stack and unacceptable in a deployment that issues real
// credentials, and "unacceptable" has to mean the process refuses to start
// rather than logs a warning nobody reads.
//
// It is deliberately a build tag and not a config key. A config key that says
// "this is production" can be set wrongly, forgotten, or overridden by an
// environment variable, and facetec-api already removed one such flag
// (logging.production) for being three unrelated switches in a trench coat.
// A build tag is decided once, by whoever builds the image, and cannot be
// changed by the deployment it is handed to.
//
// Build a production binary with:
//
//	go build -tags production ./cmd/server
//
// The Dockerfile does this, so every container image is a production build.
package buildmode

// Production reports whether the production build tag was set.
func Production() bool { return production }
