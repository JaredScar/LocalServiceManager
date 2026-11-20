#Requires -RunAsAdministrator
# Removes the service and the collector task. Leaves config.json, state, collected, and logs in place.

$ErrorActionPreference = 'Continue'
Stop-Service svcdash -Force -ErrorAction SilentlyContinue
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssm) { & nssm remove svcdash confirm | Out-Null }
Unregister-ScheduledTask -TaskName 'svcdash-collector' -TaskPath '\svcdash\' -Confirm:$false -ErrorAction SilentlyContinue
