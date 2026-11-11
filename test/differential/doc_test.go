// Package differential checks that what Docker reads of a request YorvoGate forwards is what
// YorvoGate decided on. A scoped gate runs in front of Docker's own API server code (moby's routers,
// mux and decoders, at the Engine version CI installs), whose backends record what they're handed
// instead of acting on it.
package differential
