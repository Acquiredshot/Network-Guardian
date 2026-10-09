$baseUrl = $env:INGESTION_API_URL ?? "http://localhost:8000"
try {
    Invoke-WebRequest -Method Get -Uri "$baseUrl/api/readiness" -UseBasicParsing
} catch {
    $_.Exception.Response
}
