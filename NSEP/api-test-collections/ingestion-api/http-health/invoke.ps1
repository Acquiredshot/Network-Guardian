$baseUrl = $env:INGESTION_API_URL ?? "http://localhost:8000"
Invoke-RestMethod -Method Get -Uri "$baseUrl/api/health"
