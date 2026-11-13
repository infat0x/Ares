[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source = 'public class AresAskpass { public static void Main() { System.Console.OutputEncoding = new System.Text.UTF8Encoding(false); System.Console.WriteLine(System.Environment.GetEnvironmentVariable("ARES_SSH_PASSWORD")); } }'
Add-Type -TypeDefinition $source -OutputAssembly $OutputPath -OutputType ConsoleApplication
