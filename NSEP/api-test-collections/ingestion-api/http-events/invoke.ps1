$baseUrl = $env:INGESTION_API_URL ?? "http://localhost:8000"
$body = Get-Content "$PSScriptRoot/sample-data.json" -Raw
Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/events" -ContentType "application/json" -Body $body
