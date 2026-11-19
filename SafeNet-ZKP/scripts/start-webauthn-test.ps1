$ErrorActionPreference = 'Stop'

$testConnection = [Environment]::GetEnvironmentVariable('SAFENET_TEST_CONNECTION_STRING')
if ([string]::IsNullOrWhiteSpace($testConnection)) {
    throw 'Configure SAFENET_TEST_CONNECTION_STRING para o banco isolado antes de iniciar.'
}
$builder = [System.Data.Common.DbConnectionStringBuilder]::new()
$builder.set_ConnectionString($testConnection)
if ($builder['Host'] -ne '127.0.0.1' -or $builder['Port'] -ne '5433' -or $builder['Database'] -ne 'safenet_zkp_test') {
    throw 'A conexão deve apontar para safenet_zkp_test em 127.0.0.1:5433.'
}

$oldConnection = $env:ConnectionStrings__DefaultConnection
$oldEnvironment = $env:ASPNETCORE_ENVIRONMENT
$oldLogging = $env:Logging__LogLevel__Default
try {
    $env:ConnectionStrings__DefaultConnection = $testConnection
    $env:ASPNETCORE_ENVIRONMENT = 'Development'
    $env:Logging__LogLevel__Default = 'Warning'
    $apiProject = Join-Path $PSScriptRoot '../SafeNetZKP.Api/SafeNetZKP.Api.csproj'
    Write-Host 'Abra http://localhost:4200/webauthn-test/index.html depois que a API iniciar. Para parar, pressione Ctrl+C.'
    dotnet run --project $apiProject --no-launch-profile --urls http://localhost:4200
    if ($LASTEXITCODE -ne 0) { throw 'A API de teste não iniciou corretamente.' }
}
finally {
    $env:ConnectionStrings__DefaultConnection = $oldConnection
    $env:ASPNETCORE_ENVIRONMENT = $oldEnvironment
    $env:Logging__LogLevel__Default = $oldLogging
}
