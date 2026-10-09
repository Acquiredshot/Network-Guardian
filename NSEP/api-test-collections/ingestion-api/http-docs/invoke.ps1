$baseUrl = $env:INGESTION_API_URL ?? "http://localhost:8000"
Start-Process "$baseUrl/api/docs"
