import Config

config :conformance, Conformance.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4000],
  server: true,
  secret_key_base: String.duplicate("a", 64),
  debug_errors: true
