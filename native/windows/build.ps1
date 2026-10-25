$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'LocalShare.RadioHelper\LocalShare.RadioHelper.csproj'
$config = Join-Path $PSScriptRoot 'NuGet.Config'
dotnet publish $project -c Release --self-contained false --configfile $config
Write-Host 'Windows Bluetooth/Wi-Fi Direct helper built successfully.'
