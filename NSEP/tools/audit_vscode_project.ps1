$ErrorActionPreference = "Stop"
$Root = (Get-Location).Path
$AuditFile = Join-Path $Root "SEP_VSCODE_AUDIT.txt"
$ExcludedDirs = @(".git", ".venv", "venv", "env", "__pycache__", "node_modules")
$ExcludedFileNames = @(".env", "SEP_VSCODE_AUDIT.txt")

$AuditFiles = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
    $_.FullName -notmatch '\\(\.git|\.venv|venv|env|__pycache__|node_modules)\\' -and
    $_.Name -notin $ExcludedFileNames -and
    $_.Name -notmatch '.*\.(key|pem|pfx)$'
}

"==================================================" | Out-File $AuditFile
"SEP - VS CODE PROJECT AUDIT" | Out-File $AuditFile -Append
"Generated: $(Get-Date)" | Out-File $AuditFile -Append
"==================================================" | Out-File $AuditFile -Append

"`n=== PROJECT LOCATION ===" | Out-File $AuditFile -Append
$Root | Out-File $AuditFile -Append

"`n=== PROJECT TREE ===" | Out-File $AuditFile -Append
$AuditFiles | ForEach-Object {
    $_.FullName.Substring($Root.Length).TrimStart([char[]]@('\', '/'))
} | Sort-Object | Out-File $AuditFile -Append

"`n=== PYTHON FILES ===" | Out-File $AuditFile -Append
$AuditFiles | Where-Object Extension -eq ".py" | ForEach-Object {
    "`n--- $($_.FullName) ---" | Out-File $AuditFile -Append
    Get-Content $_.FullName | Out-File $AuditFile -Append
}

"`n=== REQUIREMENTS ===" | Out-File $AuditFile -Append
foreach ($file in @("requirements.txt", "requirements-dev.txt", "pyproject.toml", "package.json", "docker-compose.yml", "docker-compose.yaml", "Dockerfile")) {
    if (Test-Path $file) {
        "`n--- $file ---" | Out-File $AuditFile -Append
        Get-Content $file | Out-File $AuditFile -Append
    }
}

"`n=== GIT STATUS ===" | Out-File $AuditFile -Append
if (Test-Path ".git") {
    git status --short | Out-File $AuditFile -Append
    "`n=== GIT BRANCH ===" | Out-File $AuditFile -Append
    git branch --show-current | Out-File $AuditFile -Append
}

"`n=== FASTAPI / UVICORN REFERENCES ===" | Out-File $AuditFile -Append
$AuditFiles | Where-Object { $_.Extension -in @(".py", ".toml", ".txt") } |
    Select-String -Pattern "FastAPI|APIRouter|uvicorn|BaseModel|@app\.|@router\." |
    ForEach-Object { "$($_.Path):$($_.LineNumber): $($_.Line.Trim())" } |
    Out-File $AuditFile -Append

"`n==================================================" | Out-File $AuditFile -Append
"AUDIT COMPLETE" | Out-File $AuditFile -Append
"==================================================" | Out-File $AuditFile -Append

Write-Host "SEP audit complete." -ForegroundColor Green
Write-Host "Audit file: $AuditFile" -ForegroundColor Cyan
