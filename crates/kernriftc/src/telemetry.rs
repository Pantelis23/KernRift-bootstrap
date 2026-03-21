// Re-export from the library so the binary and integration tests share one
// implementation.  The binary uses this module for the path-write call in
// run_backend_emit; integration tests import from `kernriftc` directly.
pub(crate) use kernriftc::collect_telemetry as collect;
