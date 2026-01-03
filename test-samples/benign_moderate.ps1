# Moderate complexity benign script
# Log file analyzer and cleanup utility

param(
    [Parameter(Mandatory=$true)]
    [string]$LogPath,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysToKeep = 30
)

function Write-LogMessage {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

function Analyze-LogFiles {
    param([string]$Path)
    
    Write-LogMessage "Starting log file analysis for path: $Path"
    
    if (-not (Test-Path $Path)) {
        Write-LogMessage "Path does not exist: $Path" "ERROR"
        return
    }
    
    $logFiles = Get-ChildItem -Path $Path -Filter "*.log" -Recurse
    $totalSize = 0
    $fileCount = 0
    
    foreach ($file in $logFiles) {
        $totalSize += $file.Length
        $fileCount++
        
        # Check if file is older than retention period
        $cutoffDate = (Get-Date).AddDays(-$DaysToKeep)
        if ($file.LastWriteTime -lt $cutoffDate) {
            Write-LogMessage "Old file found: $($file.FullName)" "WARN"
        }
    }
    
    $totalSizeMB = [math]::Round($totalSize / 1MB, 2)
    Write-LogMessage "Analysis complete. Files: $fileCount, Total size: $totalSizeMB MB"
    
    return @{
        FileCount = $fileCount
        TotalSizeMB = $totalSizeMB
        OldFiles = $logFiles | Where-Object {$_.LastWriteTime -lt $cutoffDate}
    }
}

# Main execution
try {
    $results = Analyze-LogFiles -Path $LogPath
    
    if ($results.OldFiles.Count -gt 0) {
        Write-LogMessage "Found $($results.OldFiles.Count) files older than $DaysToKeep days"
        
        $confirmation = Read-Host "Do you want to delete old files? (y/N)"
        if ($confirmation -eq 'y' -or $confirmation -eq 'Y') {
            foreach ($oldFile in $results.OldFiles) {
                Remove-Item $oldFile.FullName -Force
                Write-LogMessage "Deleted: $($oldFile.FullName)"
            }
        }
    }
    
    Write-LogMessage "Log analysis completed successfully"
}
catch {
    Write-LogMessage "Error occurred: $($_.Exception.Message)" "ERROR"
    exit 1
}