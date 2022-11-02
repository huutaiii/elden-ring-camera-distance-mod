
param (
    [Parameter(Mandatory=$true)][string]$SolutionDir,
    [Parameter(Mandatory=$true)][string]$TargetName,
    [string]$Configuration = "Debug",
    [string]$Platform = "x64",
    [string]$DeleteConfig = $false
)

$SolutionDir = $SolutionDir.TrimEnd("\\")

if (Test-Path "$SolutionDir\install_dir.txt")
{
    $SourcePath = "$SolutionDir\$Platform\$Configuration\$TargetName.dll" # ???
    $TargetDir = Get-Content -Path "$SolutionDir\install_dir.txt"
    $TargetPath = "$TargetDir\$TargetName.dll"
    # echo src=$SourcePath, target=$TargetPath
    Write-Output "Info: Installing file $SourcePath to $TargetPath"
    Copy-Item -Path "$SourcePath" -Destination "$TargetPath" # overwrites by default unless read-only
    if ($DeleteConfig -eq $true)
    {
        Write-Output "Info: Removing config at $TargetDir\$TargetName\config.ini"
        Remove-Item -Recurse -Path "$TargetDir\$TargetName\config.ini"
    }
}
else
{
    Write-Output "Info: $SolutionDir\install_dir.txt not found. Put a path (including 'Game\mods') in install_dir.txt to install the mod there automatically."
}


