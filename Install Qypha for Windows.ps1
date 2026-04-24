#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$SetupScript = Join-Path $Root "setup_windows.ps1"

if (-not (Test-Path -LiteralPath $SetupScript)) {
    [System.Windows.Forms.MessageBox]::Show(
        "setup_windows.ps1 was not found next to Install Qypha for Windows.ps1.",
        "Qypha Setup",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}

function Start-QyphaSetup {
    param(
        [string[]]$Arguments = @()
    )

    $argumentList = @(
        "-NoProfile"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        "`"$SetupScript`""
    ) + $Arguments

    Start-Process -FilePath "powershell.exe" -ArgumentList $argumentList -Verb RunAs
    $script:Form.Close()
}

$script:Form = New-Object System.Windows.Forms.Form
$script:Form.Text = "Qypha Windows Setup"
$script:Form.StartPosition = "CenterScreen"
$script:Form.Size = New-Object System.Drawing.Size(460, 310)
$script:Form.FormBorderStyle = "FixedDialog"
$script:Form.MaximizeBox = $false
$script:Form.MinimizeBox = $false
$script:Form.BackColor = [System.Drawing.Color]::FromArgb(15, 23, 42)
$script:Form.ForeColor = [System.Drawing.Color]::White

$title = New-Object System.Windows.Forms.Label
$title.Text = "Qypha Setup Wizard"
$title.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(24, 20)
$script:Form.Controls.Add($title)

$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = "Choose what you want to do. The existing setup script will handle the real install or uninstall work."
$subtitle.Size = New-Object System.Drawing.Size(390, 40)
$subtitle.Location = New-Object System.Drawing.Point(24, 56)
$subtitle.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$script:Form.Controls.Add($subtitle)

function New-WizardButton {
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [ScriptBlock]$OnClick
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Size = New-Object System.Drawing.Size(180, 42)
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.FlatStyle = "Flat"
    $button.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
    $button.ForeColor = [System.Drawing.Color]::White
    $button.Add_Click($OnClick)
    $script:Form.Controls.Add($button)
}

New-WizardButton -Text "Full Install" -X 24 -Y 120 -OnClick {
    Start-QyphaSetup @()
}

New-WizardButton -Text "CLI Only" -X 220 -Y 120 -OnClick {
    Start-QyphaSetup @("-SkipDesktop")
}

New-WizardButton -Text "Build Without App Install" -X 24 -Y 176 -OnClick {
    Start-QyphaSetup @("-SkipDesktopInstall")
}

New-WizardButton -Text "Uninstall" -X 220 -Y 176 -OnClick {
    Start-QyphaSetup @("-Uninstall")
}

$footer = New-Object System.Windows.Forms.Label
$footer.Text = "Runs setup_windows.ps1 as Administrator in a new PowerShell window."
$footer.Size = New-Object System.Drawing.Size(390, 24)
$footer.Location = New-Object System.Drawing.Point(24, 234)
$footer.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$script:Form.Controls.Add($footer)

[void]$script:Form.ShowDialog()
