<#
  .SYNOPSIS
  Windows Credential Manager Module

  .DESCRIPTION
  Exports a function to get a PSCredential object from a generic credential stored in Windows Credential Manager.

  .NOTES
  Adapted from: https://gist.github.com/toburger/2947424

  Author: Frank Peter Schultze
  Date: 2016-12-19
  Version: 1.0
#>

#region Initialize module scope

$CustomType = @{
    MemberDefinition = @'

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NativeCredential
{
  public UInt32 Flags;
  public CRED_TYPE Type;
  public IntPtr TargetName;
  public IntPtr Comment;
  public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
  public UInt32 CredentialBlobSize;
  public IntPtr CredentialBlob;
  public UInt32 Persist;
  public UInt32 AttributeCount;
  public IntPtr Attributes;
  public IntPtr TargetAlias;
  public IntPtr UserName;

  internal static NativeCredential GetNativeCredential(Credential cred)
  {
    NativeCredential ncred = new NativeCredential();
    ncred.AttributeCount = 0;
    ncred.Attributes = IntPtr.Zero;
    ncred.Comment = IntPtr.Zero;
    ncred.TargetAlias = IntPtr.Zero;
    ncred.Type = CRED_TYPE.GENERIC;
    ncred.Persist = (UInt32)1;
    ncred.CredentialBlobSize = (UInt32)cred.CredentialBlobSize;
    ncred.TargetName = Marshal.StringToCoTaskMemUni(cred.TargetName);
    ncred.CredentialBlob = Marshal.StringToCoTaskMemUni(cred.CredentialBlob);
    ncred.UserName = Marshal.StringToCoTaskMemUni(System.Environment.UserName);
    return ncred;
  }
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct Credential
{
  public UInt32 Flags;
  public CRED_TYPE Type;
  public string TargetName;
  public string Comment;
  public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
  public UInt32 CredentialBlobSize;
  public string CredentialBlob;
  public UInt32 Persist;
  public UInt32 AttributeCount;
  public IntPtr Attributes;
  public string TargetAlias;
  public string UserName;
}

public enum CRED_TYPE : uint
{
  GENERIC = 1,
  DOMAIN_PASSWORD = 2,
  DOMAIN_CERTIFICATE = 3,
  DOMAIN_VISIBLE_PASSWORD = 4,
  GENERIC_CERTIFICATE = 5,
  DOMAIN_EXTENDED = 6,
  MAXIMUM = 7,      // Maximum supported cred type
  MAXIMUM_EX = (MAXIMUM + 1000),  // Allow new applications to run on old OSes
}

public class CriticalCredentialHandle : Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid
{
  public CriticalCredentialHandle(IntPtr preexistingHandle)
  {
    SetHandle(preexistingHandle);
  }

  public Credential GetCredential()
  {
    if (!IsInvalid)
    {
      NativeCredential ncred = (NativeCredential)Marshal.PtrToStructure(handle, typeof(NativeCredential));
      Credential cred = new Credential();
      cred.CredentialBlobSize = ncred.CredentialBlobSize;
      cred.CredentialBlob = Marshal.PtrToStringUni(ncred.CredentialBlob, (int)ncred.CredentialBlobSize / 2);
      cred.UserName = Marshal.PtrToStringUni(ncred.UserName);
      cred.TargetName = Marshal.PtrToStringUni(ncred.TargetName);
      cred.TargetAlias = Marshal.PtrToStringUni(ncred.TargetAlias);
      cred.Type = ncred.Type;
      cred.Flags = ncred.Flags;
      cred.Persist = ncred.Persist;

      return cred;
    }
    else
    {
      throw new InvalidOperationException("Invalid CriticalHandle!");
    }
  }

  override protected bool ReleaseHandle()
  {
    if (!IsInvalid)
    {
      CredFree(handle);
      SetHandleAsInvalid();

      return true;
    }
    return false;
  }
}

[DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CredRead(string target, CRED_TYPE type, int reservedFlag, out IntPtr CredentialPtr);

[DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
public static extern bool CredFree([In] IntPtr cred);
'@
    Namespace = 'ADVAPI32'
    Name = 'Util'
  }
try
{
  Add-Type @CustomType -ErrorAction Stop
}
catch
{
  $_.Exception.Message | Write-Error
  exit
}

#endregion


#region Public functions

<#
  .SYNOPSIS
  Get a PowerShell Credential from the Windows Credential Manager

  .DESCRIPTION
  Get-StoredCredential returns a PSCredential object from a generic credential stored in Windows Credential Manager.

  .EXAMPLE
  Get-StoredCredential codeplexuser

  UserName                             Password
  --------                             --------
  codeplexuser                         System.Security.SecureString

  .EXAMPLE
  $cred = Get-StoredCredential production
  $conn = Connect-WSMan -ComputerName ProdServer -Credential $cred

  .NOTES
  The function can only access Generic Credentials.
#>
function Get-StoredCredential
{
  [CmdletBinding()]
  [OutputType([PSCredential])]
  Param
  (
    # The name of the credential (i.e. servername, internet adress, or network address)
    [Parameter(Mandatory)]
    [string]$Name
  )

  $OutputObject = $null
  $ErrorActionPreference = 'Stop'
  try
  {
    $nCredPtr = New-Object -TypeName IntPtr

    if ([ADVAPI32.Util]::CredRead($Name,1,0,[ref] $nCredPtr))
    {
      $critCred = New-Object ADVAPI32.Util+CriticalCredentialHandle $nCredPtr
      $cred = $critCred.GetCredential()
      $username = $cred.UserName
      $securePassword = $cred.CredentialBlob | ConvertTo-SecureString -AsPlainText -Force

      $OutputObject = New-Object -TypeName pscredential -ArgumentList $username, $securePassword
    }
    else
    {
      'No credentials were found in Windows Credential Manager for TargetName: {0}' -f $Name | Write-Warning
    }
  }
  catch
  {
    $_.Exception.Message | Write-Error
  }
  finally
  {
    $OutputObject
  }
}

#endregion


#region Export module members

Export-ModuleMember -Function *-StoredCredential

#endregion
