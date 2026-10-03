/**
 * Tell Express how many reverse proxies sit in front of the app, so `req.ip`
 * is the real client address.
 *
 * X-Forwarded-For is a list each proxy appends to; anything before the entries
 * our own proxies added is supplied by the client and can be faked. With N
 * trusted hops Express takes the Nth entry from the right - the address our
 * outermost proxy saw - and ignores the rest. With 0 (local development, no
 * proxy) the header is ignored and the socket address is used.
 *
 * Set TRUST_PROXY_HOPS to the number of proxies in front of the app.
 * Too low is safe (logs a proxy's address); too high lets clients fake their IP.
 */
export function configureTrustProxy(app, env = process.env) {
  const hops = Number.parseInt(env.TRUST_PROXY_HOPS ?? "0", 10);
  app.set("trust proxy", Number.isInteger(hops) && hops > 0 ? hops : false);
}
