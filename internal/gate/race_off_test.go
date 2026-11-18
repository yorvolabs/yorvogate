//go:build !race

package gate

// raceBuild is whether the tests run with the race detector, which inflates what they allocate.
const raceBuild = false
