param(
    [string]$IncidentId = "00000000-0000-0000-0000-000000000000"
)
$baseUrl = $env:INGESTION_API_URL ?? "http://localhost:8000"
try {
    Invoke-WebRequest -Method Get -Uri "$baseUrl/api/v1/incidents/$IncidentId" -UseBasicParsing
} catch {
    $_.Exception.Response
}
