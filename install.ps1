
param (
    [Parameter(Mandatory=$true)][string]$SolutionDir,
    [Parameter(Mandatory=$true)][string]$TargetName,
    [string]$Configuration = "Debug",
    [string]$Platform = "x64",
    [switch]$DeleteConfig = $false
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

    $ConfigPath = "$TargetDir\$TargetName\config.ini"
    if ($DeleteConfig)
    {
        if (Test-Path "$ConfigPath")
        {
            Write-Output "Info: Removing config at $ConfigPath"
            Remove-Item -Recurse -Path "$ConfigPath"
        }
        else
        {
            Write-Output "Info: config file doesn't exist"
        }
    }
}
else
{
    Write-Output "Info: $SolutionDir\install_dir.txt not found. Put a path (including 'Game\mods') in install_dir.txt to install the mod there automatically."
}


