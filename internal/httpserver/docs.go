package httpserver

import (
	_ "embed"
	"net/http"
)

//go:embed docs/openapi.yaml
var openapiSpec []byte

func serveOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(openapiSpec)
}

const swaggerUIHTML = `<!doctype html>
<html>
<head>
	<meta charset="utf-8" />
	<title>auth-2fa-api docs</title>
	<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body style="margin:0">
	<div id="swagger-ui"></div>
	<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
	<script>
		window.onload = () => {
			window.ui = SwaggerUIBundle({
				url: "/openapi.yaml",
				dom_id: "#swagger-ui",
			});
		};
	</script>
</body>
</html>`

func serveDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerUIHTML))
}
