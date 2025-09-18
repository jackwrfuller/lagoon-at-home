mirrors:
  "registry.${BASE_URL}":
    endpoint:
      - "https://registry.${BASE_URL}"

configs:
  "registry.${BASE_URL}":
    tls:
      insecure_skip_verify: true
