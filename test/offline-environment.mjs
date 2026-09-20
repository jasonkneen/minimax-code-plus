// Proxy setup installs undici.fetch over the preloaded offline mock.
// Keep host proxy settings out of isolated CLI children without changing the parent.
export function withoutProxyEnvironment(environment = process.env) {
  return {
    ...environment,
    HTTP_PROXY: "",
    HTTPS_PROXY: "",
    ALL_PROXY: "",
    NO_PROXY: "",
    http_proxy: "",
    https_proxy: "",
    all_proxy: "",
    no_proxy: "",
  };
}
