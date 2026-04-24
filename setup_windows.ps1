#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$SkipDesktop,
    [switch]$SkipBuild,
    [switch]$BuildDesktopBundle,
    [switch]$SkipDesktopInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$EmbeddedRuntime = Join-Path $Root "embedded_runtime"
$DesktopApp = Join-Path $Root "apps\qypha-desktop"
$NodeVersion = [Version]"22.16.0"
$ProtocVersion = "28.3"
$LocalToolsDir = Join-Path $env:USERPROFILE ".qypha-tools"
$LocalBinDir = Join-Path $LocalToolsDir "bin"
$DesktopDir = [Environment]::GetFolderPath("DesktopDirectory")
if (-not $DesktopDir) {
    $DesktopDir = Join-Path $env:USERPROFILE "Desktop"
}
$InstallDesktopApp = (-not $SkipDesktop) -and (-not $SkipDesktopInstall)
$ShouldBuildDesktopBundle = (-not $SkipDesktop)
$InstalledDesktopPath = $null
$DesktopShortcutPath = $null
$TerminalCliLauncher = $null
$TerminalDesktopLauncher = $null
$script:NodeExe = $null
$script:NpmCmd = $null

function Write-Banner {
    Write-Host ""
    Write-Host "  +--------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |                 Qypha Windows Setup            |" -ForegroundColor Cyan
    Write-Host "  |          Source bootstrap + runtime build       |" -ForegroundColor Cyan
    Write-Host "  +--------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step($num, $total, $message) {
    Write-Host "[$num/$total] " -NoNewline -ForegroundColor Yellow
    Write-Host $message
}

function Write-Info($message) {
    Write-Host "  - $message" -ForegroundColor DarkGray
}

function Write-Ok($message) {
    Write-Host "  OK  $message" -ForegroundColor Green
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CommandExists($Name) {
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Refresh-Path {
    $machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    $env:PATH = "$machinePath;$userPath"
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if (Test-Path $cargoBin) {
        $env:PATH = "$cargoBin;$env:PATH"
    }
    if (Test-Path $LocalBinDir) {
        $env:PATH = "$LocalBinDir;$env:PATH"
    }
}

function Ensure-UserPathContains {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathEntry
    )

    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    $parts = @()
    if ($userPath) {
        $parts = $userPath.Split(";") | Where-Object { $_ -and $_.Trim() -ne "" }
    }
    if ($parts -notcontains $PathEntry) {
        $newUserPath = if ($userPath -and $userPath.Trim()) {
            "$userPath;$PathEntry"
        } else {
            $PathEntry
        }
        [Environment]::SetEnvironmentVariable("PATH", $newUserPath, "User")
    }
    Refresh-Path
}

function Ensure-Admin {
    if (-not (Test-Admin)) {
        throw "This script must be run as Administrator."
    }
}

function Remove-PathIfExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path -LiteralPath $Path) {
        Write-Info "Removing $Path"
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    }
}

function Remove-MatchingPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Patterns
    )

    foreach ($pattern in $Patterns) {
        $items = Get-ChildItem -Path $pattern -Force -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            if ($item -and (Test-Path -LiteralPath $item.FullName)) {
                Write-Info "Removing $($item.FullName)"
                Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
            }
        }
    }
}

function Clean-ProjectArtifacts {
    Write-Info "Removing repo build artifacts and generated runtime payloads..."

    Remove-MatchingPaths -Patterns @(
        (Join-Path $Root "target"),
        (Join-Path $EmbeddedRuntime "dist"),
        (Join-Path $EmbeddedRuntime "node_modules"),
        (Join-Path $DesktopApp "dist"),
        (Join-Path $DesktopApp "node_modules"),
        (Join-Path $DesktopApp "src-tauri\target"),
        (Join-Path $EmbeddedRuntime "internal\runtime\python\.downloads"),
        (Join-Path $EmbeddedRuntime "internal\runtime\python\*\python"),
        (Join-Path $EmbeddedRuntime "internal\runtime\git\.downloads"),
        (Join-Path $EmbeddedRuntime "internal\runtime\git\*\micromamba"),
        (Join-Path $EmbeddedRuntime "internal\runtime\git\*\pkgs"),
        (Join-Path $EmbeddedRuntime "internal\runtime\git\*\prefix"),
        (Join-Path $EmbeddedRuntime "internal\runtime\git\*\mamba-root"),
        (Join-Path $EmbeddedRuntime "internal\bundled-mcp-plugins\.runtime-state"),
        (Join-Path $EmbeddedRuntime "internal\bundled-mcp-plugins\fetch-server\vendor\site-packages"),
        (Join-Path $EmbeddedRuntime "internal\bundled-mcp-plugins\git-server\vendor\site-packages"),
        (Join-Path $EmbeddedRuntime "internal\bundled-mcp-plugins\playwright-mcp\vendor\node_modules"),
        (Join-Path $EmbeddedRuntime "internal\bundled-mcp-plugins\playwright-mcp\vendor\ms-playwright")
    )
}

function Get-OptionalPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }
    return $null
}

function Get-QyphaUninstallEntry {
    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($registryPath in $registryPaths) {
        $entry = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue |
            Where-Object {
                $displayName = Get-OptionalPropertyValue -Object $_ -Name "DisplayName"
                $displayName -and (
                    $displayName -eq "Qypha" -or
                    $displayName -like "Qypha *"
                )
            } |
            Sort-Object { Get-OptionalPropertyValue -Object $_ -Name "DisplayName" } |
            Select-Object -First 1
        if ($entry) {
            return $entry
        }
    }

    return $null
}

function Split-CommandLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandLine
    )

    if ($CommandLine -match '^\s*"([^"]+)"\s*(.*)$') {
        return @($matches[1], $matches[2].Trim())
    }
    if ($CommandLine -match '^\s*(\S+)\s*(.*)$') {
        return @($matches[1], $matches[2].Trim())
    }

    return @($CommandLine.Trim(), "")
}

function Invoke-QyphaDesktopUninstall {
    $entry = Get-QyphaUninstallEntry
    if ($entry) {
        $displayName = Get-OptionalPropertyValue -Object $entry -Name "DisplayName"
        $windowsInstaller = Get-OptionalPropertyValue -Object $entry -Name "WindowsInstaller"
        $psChildName = Get-OptionalPropertyValue -Object $entry -Name "PSChildName"
        $quietUninstallString = Get-OptionalPropertyValue -Object $entry -Name "QuietUninstallString"
        $uninstallString = Get-OptionalPropertyValue -Object $entry -Name "UninstallString"

        Write-Info "Found installed Qypha entry: $displayName"

        if ($windowsInstaller -eq 1 -and $psChildName) {
            Write-Info "Running MSI uninstall..."
            $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x", $psChildName, "/qn", "/norestart" -Wait -PassThru
            if ($proc.ExitCode -ne 0) {
                throw "MSI uninstall failed with exit code $($proc.ExitCode)."
            }
            return
        }

        $commandLine = $quietUninstallString
        $useSilentFlag = $false
        if (-not $commandLine) {
            $commandLine = $uninstallString
            $useSilentFlag = $true
        }

        if ($commandLine) {
            $parts = Split-CommandLine -CommandLine $commandLine
            $filePath = $parts[0]
            $arguments = $parts[1]

            if ($filePath -match '(?i)msiexec(\.exe)?$') {
                $arguments = $arguments -replace '(?i)/I', '/x' -replace '(?i)\s+/passive', ''
                if ($arguments -notmatch '(?i)/qn') {
                    $arguments = "$arguments /qn /norestart"
                }
            } elseif ($useSilentFlag -and $arguments -notmatch '(^|\s)/(S|quiet|qn)(\s|$)') {
                $arguments = "$arguments /S".Trim()
            }

            Write-Info "Running Qypha uninstaller..."
            $proc = Start-Process -FilePath $filePath -ArgumentList $arguments -Wait -PassThru
            if ($proc.ExitCode -ne 0) {
                throw "Qypha desktop uninstall failed with exit code $($proc.ExitCode)."
            }
            return
        }
    }

    $fallbackInstallDirs = @(
        (Join-Path ${env:ProgramFiles} "Qypha"),
        (Join-Path ${env:ProgramFiles(x86)} "Qypha"),
        (Join-Path ${env:LOCALAPPDATA} "Programs\Qypha")
    ) | Where-Object { $_ }

    foreach ($installDir in $fallbackInstallDirs) {
        $candidateUninstallers = @(
            (Join-Path $installDir "uninstall.exe"),
            (Join-Path $installDir "Uninstall Qypha.exe"),
            (Join-Path $installDir "unins000.exe")
        )
        foreach ($uninstaller in $candidateUninstallers) {
            if (Test-Path -LiteralPath $uninstaller) {
                Write-Info "Running fallback uninstaller at $uninstaller"
                $proc = Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -PassThru
                if ($proc.ExitCode -ne 0) {
                    throw "Fallback Qypha uninstaller failed with exit code $($proc.ExitCode)."
                }
                return
            }
        }
    }

    Write-Info "No installed Qypha desktop app was found."
}

function Uninstall-Qypha {
    Write-Step 1 1 "Uninstalling Qypha app and build outputs"

    Invoke-QyphaDesktopUninstall

    Remove-PathIfExists (Join-Path $DesktopDir "Qypha.lnk")
    Remove-PathIfExists (Join-Path $LocalBinDir "Qypha-desktop.cmd")
    Remove-PathIfExists (Join-Path $LocalBinDir "Qypha.cmd")
    Remove-PathIfExists (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Qypha")

    $installRoots = @(
        (Join-Path ${env:ProgramFiles} "Qypha"),
        (Join-Path ${env:ProgramFiles(x86)} "Qypha"),
        (Join-Path ${env:LOCALAPPDATA} "Programs\Qypha")
    ) | Where-Object { $_ }
    foreach ($installRoot in $installRoots) {
        Remove-PathIfExists $installRoot
    }

    Clean-ProjectArtifacts

    Write-Host ""
    Write-Host "Qypha uninstall complete." -ForegroundColor Green
    Write-Host ""
    Write-Host "Removed:" -ForegroundColor Cyan
    Write-Host "  - installed desktop app / shortcuts"
    Write-Host "  - terminal launchers under $LocalBinDir"
    Write-Host "  - repo build artifacts and generated embedded runtime payloads"
    Write-Host ""
    Write-Host "Preserved:" -ForegroundColor Cyan
    Write-Host "  - this repository folder"
    Write-Host "  - local toolchains under $LocalToolsDir"
    Write-Host "  - user data / agent state under ~/.qypha and related config dirs"
}

function Ensure-VSBuildTools {
    $vsLocations = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC"
    )
    foreach ($loc in $vsLocations) {
        if (Test-Path $loc) {
            Write-Ok "Visual Studio C++ build tools found."
            return
        }
    }

    Write-Info "Installing Visual Studio Build Tools..."
    $installer = Join-Path $env:TEMP "qypha-vs-buildtools.exe"
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_buildtools.exe" -OutFile $installer
    $args = @(
        "--quiet", "--wait", "--norestart", "--nocache",
        "--add", "Microsoft.VisualStudio.Workload.VCTools",
        "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
        "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621",
        "--includeRecommended"
    )
    $proc = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        throw "Visual Studio Build Tools installation failed with exit code $($proc.ExitCode)."
    }
    Write-Ok "Visual Studio Build Tools installed."
}

function Ensure-WebView2 {
    $paths = @(
        "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application",
        "${env:ProgramFiles}\Microsoft\EdgeWebView\Application"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Write-Ok "WebView2 Runtime found."
            return
        }
    }

    Write-Info "Installing Microsoft Edge WebView2 Runtime..."
    $installer = Join-Path $env:TEMP "qypha-webview2-setup.exe"
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $installer
    $proc = Start-Process -FilePath $installer -ArgumentList "/silent", "/install" -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "WebView2 Runtime installation failed with exit code $($proc.ExitCode)."
    }
    Write-Ok "WebView2 Runtime installed."
}

function Ensure-Rust {
    Refresh-Path
    if (-not (Test-CommandExists "rustup")) {
        Write-Info "Installing rustup + Rust stable..."
        $rustupInit = Join-Path $env:TEMP "rustup-init.exe"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInit
        $proc = Start-Process -FilePath $rustupInit -ArgumentList "-y", "--default-toolchain", "stable-x86_64-pc-windows-msvc" -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            throw "Rust installation failed with exit code $($proc.ExitCode)."
        }
        Refresh-Path
    }
    & rustup toolchain install stable | Out-Null
    & rustup default stable | Out-Null
    & rustup update stable | Out-Null
    Write-Ok ((& rustc --version).Trim())
}

function Get-NodeExecutableCandidate {
    $candidates = @()

    if (Test-CommandExists "node") {
        try {
            $cmd = Get-Command "node" -ErrorAction Stop
            if ($cmd.Source) {
                $candidates += $cmd.Source
            }
        } catch {
            # fall through to filesystem candidates
        }
    }

    $portableNodeDir = Join-Path $LocalToolsDir "node-v$($NodeVersion.ToString())-win-x64"
    $candidates += @(
        (Join-Path $portableNodeDir "node.exe"),
        (Join-Path ${env:ProgramFiles} "nodejs\node.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "nodejs\node.exe"),
        (Join-Path ${env:LOCALAPPDATA} "Programs\nodejs\node.exe")
    ) | Where-Object { $_ }

    $seen = @{}
    foreach ($candidate in $candidates) {
        if (-not $candidate -or $seen.ContainsKey($candidate) -or -not (Test-Path -LiteralPath $candidate)) {
            continue
        }
        $seen[$candidate] = $true
        try {
            $raw = (& $candidate --version).Trim().TrimStart("v")
            $current = [Version]$raw
            if ($current -ge $NodeVersion) {
                return [PSCustomObject]@{
                    Path = $candidate
                    Version = $current
                    BinDir = Split-Path -Parent $candidate
                }
            }
        } catch {
            # ignore broken candidates and continue
        }
    }

    return $null
}

function Install-PortableNode {
    $versionString = $NodeVersion.ToString()
    $archiveName = "node-v$versionString-win-x64.zip"
    $archiveUrl = "https://nodejs.org/dist/v$versionString/$archiveName"
    $zipPath = Join-Path $env:TEMP "qypha-$archiveName"
    $installDir = Join-Path $LocalToolsDir "node-v$versionString-win-x64"
    $stagingRoot = Join-Path $env:TEMP "qypha-node-stage-$([Guid]::NewGuid().ToString('N'))"

    Write-Info "Installing portable Node.js v$versionString..."
    New-Item -ItemType Directory -Force -Path $LocalToolsDir | Out-Null
    Invoke-WebRequest -Uri $archiveUrl -OutFile $zipPath

    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $stagingRoot | Out-Null
    Expand-Archive -Path $zipPath -DestinationPath $stagingRoot -Force

    $extractedDir = Join-Path $stagingRoot "node-v$versionString-win-x64"
    if (-not (Test-Path -LiteralPath $extractedDir)) {
        throw "Portable Node.js archive did not contain the expected folder node-v$versionString-win-x64."
    }

    if (Test-Path -LiteralPath $installDir) {
        Remove-Item -LiteralPath $installDir -Recurse -Force
    }
    Move-Item -LiteralPath $extractedDir -Destination $installDir
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force

    Ensure-UserPathContains -PathEntry $installDir
    Refresh-Path
}

function Resolve-NpmCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BinDir
    )

    $npmCandidates = @(
        (Join-Path $BinDir "npm.cmd"),
        (Join-Path $BinDir "npm")
    )
    foreach ($candidate in $npmCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

function Ensure-Node {
    Refresh-Path
    $nodeCandidate = Get-NodeExecutableCandidate
    if ($nodeCandidate) {
        Ensure-UserPathContains -PathEntry $nodeCandidate.BinDir
        $script:NodeExe = $nodeCandidate.Path
        $script:NpmCmd = Resolve-NpmCommand -BinDir $nodeCandidate.BinDir
        if (-not $script:NpmCmd) {
            throw "Node.js was found at $($nodeCandidate.Path) but npm could not be located in $($nodeCandidate.BinDir)."
        }
        Write-Ok "Node.js v$($nodeCandidate.Version) is ready."
        return
    }

    Install-PortableNode
    $nodeCandidate = Get-NodeExecutableCandidate
    if (-not $nodeCandidate) {
        throw "Portable Node.js installation completed but node.exe could not be located."
    }
    Ensure-UserPathContains -PathEntry $nodeCandidate.BinDir
    $script:NodeExe = $nodeCandidate.Path
    $script:NpmCmd = Resolve-NpmCommand -BinDir $nodeCandidate.BinDir
    if (-not $script:NpmCmd) {
        throw "Portable Node.js was installed but npm could not be located in $($nodeCandidate.BinDir)."
    }
    Write-Ok "Node.js v$($nodeCandidate.Version) is ready."
}

function Ensure-Protoc {
    Refresh-Path
    if (Test-CommandExists "protoc") {
        Write-Ok ((& protoc --version).Trim())
        return
    }

    Write-Info "Installing protoc v$ProtocVersion..."
    $zipPath = Join-Path $env:TEMP "qypha-protoc.zip"
    $installDir = Join-Path $env:ProgramFiles "Qypha\protoc-$ProtocVersion"
    $url = "https://github.com/protocolbuffers/protobuf/releases/download/v$ProtocVersion/protoc-$ProtocVersion-win64.zip"
    Invoke-WebRequest -Uri $url -OutFile $zipPath
    if (Test-Path $installDir) {
        Remove-Item -Recurse -Force $installDir
    }
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Expand-Archive -Path $zipPath -DestinationPath $installDir -Force
    $protocBin = Join-Path $installDir "bin"
    $machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($machinePath -notlike "*$protocBin*") {
        [Environment]::SetEnvironmentVariable("PATH", "$machinePath;$protocBin", "Machine")
    }
    Refresh-Path
    Write-Ok ((& protoc --version).Trim())
}

function Invoke-NpmCi($Path) {
    Write-Info "npm ci in $Path"
    Push-Location $Path
    try {
        & $script:NpmCmd ci
        if ($LASTEXITCODE -ne 0) {
            throw "npm ci failed in $Path"
        }
    } finally {
        Pop-Location
    }
}

function Build-EmbeddedWorker {
    Push-Location $EmbeddedRuntime
    try {
        & $script:NpmCmd run build:embedded-worker
        if ($LASTEXITCODE -ne 0) {
            throw "Embedded runtime worker build failed."
        }
    } finally {
        Pop-Location
    }
}

function Build-Web {
    Push-Location $DesktopApp
    try {
        & $script:NpmCmd run build:web
        if ($LASTEXITCODE -ne 0) {
            throw "Desktop web build failed."
        }
    } finally {
        Pop-Location
    }
}

function Build-DesktopBundle {
    Push-Location $DesktopApp
    try {
        & $script:NpmCmd run tauri:build -- --bundles nsis,msi
        if ($LASTEXITCODE -ne 0) {
            throw "Desktop bundle build failed."
        }
    } finally {
        Pop-Location
    }
}

function Get-FirstMatchingFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    $items = Get-ChildItem -Path $Pattern -ErrorAction SilentlyContinue
    if ($items) {
        return ($items | Sort-Object FullName | Select-Object -First 1).FullName
    }
    return $null
}

function Normalize-ExecutablePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RawPath
    )

    $trimmed = $RawPath.Trim().Trim('"')
    if ($trimmed -match '^(.*?\.exe)(,.*)?$') {
        return $matches[1]
    }
    return $trimmed
}

function Resolve-ShortcutTargetPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShortcutPath
    )

    if (-not (Test-Path -LiteralPath $ShortcutPath)) {
        return $null
    }

    try {
        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut($ShortcutPath)
        $targetPath = $shortcut.TargetPath
        if ($targetPath) {
            return (Normalize-ExecutablePath -RawPath $targetPath)
        }
    } catch {
        return $null
    }

    return $null
}

function Resolve-InstalledQyphaDesktopExe {
    $entry = Get-QyphaUninstallEntry
    if ($entry) {
        $displayIcon = Get-OptionalPropertyValue -Object $entry -Name "DisplayIcon"
        if ($displayIcon) {
            $iconPath = Normalize-ExecutablePath -RawPath $displayIcon
            if (Test-Path -LiteralPath $iconPath) {
                return $iconPath
            }
        }

        $installLocation = Get-OptionalPropertyValue -Object $entry -Name "InstallLocation"
        if ($installLocation -and (Test-Path -LiteralPath $installLocation)) {
            $match = Get-ChildItem -Path $installLocation -Filter "*.exe" -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -in @("Qypha.exe", "Qypha-desktop.exe", "qypha-desktop.exe") } |
                Sort-Object FullName |
                Select-Object -First 1
            if ($match) {
                return $match.FullName
            }
        }
    }

    $shortcutCandidates = @(
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Qypha\Qypha.lnk"),
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Qypha.lnk"),
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Qypha\Qypha.lnk"),
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Qypha.lnk"),
        (Join-Path $DesktopDir "Qypha.lnk")
    ) | Where-Object { $_ }

    foreach ($shortcutPath in $shortcutCandidates) {
        $shortcutTarget = Resolve-ShortcutTargetPath -ShortcutPath $shortcutPath
        if ($shortcutTarget -and (Test-Path -LiteralPath $shortcutTarget)) {
            return $shortcutTarget
        }
    }

    $candidates = @(
        (Join-Path ${env:ProgramFiles} "Qypha\Qypha.exe"),
        (Join-Path ${env:ProgramFiles} "Qypha\Qypha-desktop.exe"),
        (Join-Path ${env:ProgramFiles} "Qypha\qypha-desktop.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Qypha\Qypha.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Qypha\Qypha-desktop.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Qypha\qypha-desktop.exe"),
        (Join-Path ${env:LOCALAPPDATA} "Programs\Qypha\Qypha.exe"),
        (Join-Path ${env:LOCALAPPDATA} "Programs\Qypha\Qypha-desktop.exe"),
        (Join-Path ${env:LOCALAPPDATA} "Programs\Qypha\qypha-desktop.exe")
    ) | Where-Object { $_ }

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    $searchRoots = @(
        (Join-Path ${env:ProgramFiles} "Qypha"),
        (Join-Path ${env:ProgramFiles(x86)} "Qypha"),
        (Join-Path ${env:LOCALAPPDATA} "Programs\Qypha")
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $searchRoots) {
        $match = Get-ChildItem -Path $root -Filter "*.exe" -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in @("Qypha.exe", "Qypha-desktop.exe", "qypha-desktop.exe") } |
            Sort-Object FullName |
            Select-Object -First 1
        if ($match) {
            return $match.FullName
        }
    }

    return $null
}

function New-DesktopShortcut {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath
    )

    $shortcutPath = Join-Path $DesktopDir "Qypha.lnk"
    $wshShell = New-Object -ComObject WScript.Shell
    $shortcut = $wshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $TargetPath
    $shortcut.WorkingDirectory = Split-Path -Parent $TargetPath
    $shortcut.IconLocation = $TargetPath
    $shortcut.Save()
    return $shortcutPath
}

function New-TerminalDesktopLauncher {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath
    )

    New-Item -ItemType Directory -Force -Path $LocalBinDir | Out-Null
    $launcherPath = Join-Path $LocalBinDir "Qypha-desktop.cmd"
    @"
@echo off
start "" "$TargetPath" %*
"@ | Set-Content -Path $launcherPath -Encoding ASCII
    Ensure-UserPathContains -PathEntry $LocalBinDir
    return $launcherPath
}

function New-TerminalCliLauncher {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath
    )

    New-Item -ItemType Directory -Force -Path $LocalBinDir | Out-Null
    $launcherPath = Join-Path $LocalBinDir "Qypha.cmd"
    @"
@echo off
"$TargetPath" %*
"@ | Set-Content -Path $launcherPath -Encoding ASCII
    Ensure-UserPathContains -PathEntry $LocalBinDir
    return $launcherPath
}

function Install-DesktopApplication {
    if (-not $InstallDesktopApp) {
        return
    }
    if ($SkipBuild) {
        return
    }

    $bundleRoot = Join-Path $DesktopApp "src-tauri\target\release\bundle"
    $nsisInstaller = Get-FirstMatchingFile -Pattern (Join-Path $bundleRoot "nsis\*.exe")
    $msiInstaller = Get-FirstMatchingFile -Pattern (Join-Path $bundleRoot "msi\*.msi")

    if ($nsisInstaller) {
        Write-Info "Installing Qypha desktop app via NSIS installer..."
        $proc = Start-Process -FilePath $nsisInstaller -ArgumentList "/S" -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            throw "NSIS desktop installer failed with exit code $($proc.ExitCode)."
        }
    } elseif ($msiInstaller) {
        Write-Info "Installing Qypha desktop app via MSI..."
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "`"$msiInstaller`"", "/qn", "/norestart" -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            throw "MSI desktop installer failed with exit code $($proc.ExitCode)."
        }
    } else {
        throw "No desktop installer bundle found under $bundleRoot"
    }

    $installedExe = $null
    for ($attempt = 0; $attempt -lt 15; $attempt++) {
        if ($attempt -gt 0) {
            Start-Sleep -Seconds 1
        }
        $installedExe = Resolve-InstalledQyphaDesktopExe
        if ($installedExe) {
            break
        }
    }
    if (-not $installedExe) {
        throw "Desktop app installed but the Qypha executable could not be located."
    }

    $script:InstalledDesktopPath = $installedExe
    $script:DesktopShortcutPath = New-DesktopShortcut -TargetPath $installedExe
    $script:TerminalDesktopLauncher = New-TerminalDesktopLauncher -TargetPath $installedExe
}

Write-Banner
Ensure-Admin

if ($Uninstall) {
    Uninstall-Qypha
    exit 0
}

Write-Step 1 9 "Checking Windows prerequisites"
Ensure-VSBuildTools
if (-not $SkipDesktop) {
    Ensure-WebView2
}

Write-Step 2 9 "Checking Rust toolchain"
Ensure-Rust

Write-Step 3 9 "Checking Node.js"
Ensure-Node

Write-Step 4 9 "Checking protoc"
Ensure-Protoc

Write-Step 5 9 "Installing npm dependencies"
Invoke-NpmCi $EmbeddedRuntime
if (-not $SkipDesktop) {
    Invoke-NpmCi $DesktopApp
}

Write-Step 6 9 "Building embedded AI worker"
Build-EmbeddedWorker

if (-not $SkipBuild) {
    Write-Step 7 9 "Building Rust core"
    Push-Location $Root
    try {
        & cargo build --release
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build --release failed."
        }
        $cliTarget = Join-Path $Root "target\release\qypha.exe"
        if (Test-Path -LiteralPath $cliTarget) {
            $script:TerminalCliLauncher = New-TerminalCliLauncher -TargetPath $cliTarget
        }
    } finally {
        Pop-Location
    }

    if (-not $SkipDesktop) {
        Write-Info "Building desktop web assets"
        Build-Web
        if ($ShouldBuildDesktopBundle) {
            Write-Info "Building desktop installer bundle"
            Build-DesktopBundle
        }
    }
} else {
    Write-Step 7 9 "Skipping build steps"
}

Write-Step 8 9 "Installing desktop application"
if (-not $SkipDesktop) {
    Install-DesktopApplication
}

Write-Step 9 9 "Setup complete"
Write-Host ""
Write-Host "Qypha is ready." -ForegroundColor Green
Write-Host ""
Write-Host "CLI:" -ForegroundColor Cyan
if ($TerminalCliLauncher) {
    Write-Host "  Terminal launch: $TerminalCliLauncher"
    Write-Host "  Or simply: Qypha launch"
} else {
    Write-Host "  cd $Root"
    Write-Host "  cargo run --release -- launch"
}
Write-Host ""
if (-not $SkipDesktop) {
    Write-Host "Desktop App:" -ForegroundColor Cyan
    if ($InstalledDesktopPath) {
        Write-Host "  Installed app: $InstalledDesktopPath"
    }
    if ($DesktopShortcutPath) {
        Write-Host "  Desktop shortcut: $DesktopShortcutPath"
    }
    if ($TerminalDesktopLauncher) {
        Write-Host "  Terminal launch: $TerminalDesktopLauncher"
        Write-Host "  Or simply: Qypha-desktop"
    }
    Write-Host ""
    Write-Host "Desktop dev mode:" -ForegroundColor Cyan
    Write-Host "  cd $DesktopApp"
    Write-Host "  npm run tauri:dev"
    Write-Host ""
}
