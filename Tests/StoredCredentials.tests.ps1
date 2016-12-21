$ModuleRoot = Split-Path -Parent $PSScriptRoot
$ModuleFile = (Split-Path -Leaf $PSCommandPath) -replace '\.tests\.ps1$', '.psm1'
Import-Module "$ModuleRoot\$ModuleFile"


$TestCred = @{
  Target = [guid]::NewGuid().Guid
  UserName = 'foo/bar'
  Password = 'foobar'
}

Describe 'Get-StoredCredential' {

  # Create test credential
  $ProcessParam = @('/generic:{0} /user:{1} /pass:{2}' -f $TestCred.Target, $TestCred.UserName, $TestCred.Password)
  Start-Process -FilePath cmdkey.exe -ArgumentList $ProcessParam -Wait -NoNewWindow

  Context 'Running with existing credentials' {
    It 'returns pscredential object' {
      Get-StoredCredential -Name $TestCred.Target | Should BeOfType pscredential
    }
  }

  # Remove test credential
  $ProcessParam = @('/delete:{0}' -f $TestCred.Target)
  Start-Process -FilePath cmdkey.exe -ArgumentList $ProcessParam -Wait -NoNewWindow

  Context 'Running with non-existing credentials' {
    It 'displays warning and returns $null' {
      Get-StoredCredential -Name $TestCred.Target | Should BeNullOrEmpty
    }
  }
}
