function Invoke-MoveMouse {
  <#
  @AUTHOR: Bret McDanel
  .SYNOPSIS
  Randomly moves the mouse
  .DESCRIPTION
  Randomly moves the mouse
  #>
  Add-Type -AssemblyName System.Windows.Forms

  Write-Host "Starting mouse movement in 5 seconds..."
  Start-Sleep -Seconds 5
  Write-Host "Moving mouse"

  while ($true) {
    $X = (Get-Random -Maximum ([System.Windows.Forms.SystemInformation]::VirtualScreen.Width))
    $Y = (Get-Random -Maximum ([System.Windows.Forms.SystemInformation]::VirtualScreen.Height))

    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point($X, $Y)
    Start-Sleep -Seconds (Get-Random -Maximum 5)
  }
}