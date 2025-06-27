#!/bin/bash
# serve-docs.sh - Serve the MkDocs documentation

echo "Starting MkDocs documentation server..."
echo "Documentation will be available at: http://localhost:8002"
echo "Press Ctrl+C to stop the server"
echo ""

uv run mkdocs serve --dev-addr=0.0.0.0:8101
