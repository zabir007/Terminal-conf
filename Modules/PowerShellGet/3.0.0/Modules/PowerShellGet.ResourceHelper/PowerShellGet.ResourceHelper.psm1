#
# Copyright (c) Microsoft Corporation.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

<#
    Helper functions for PowerShellGet DSC Resources.
#>

# Import localization helper functions.
$helperName = 'PowerShellGet.LocalizationHelper'
$resourceModuleRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$dscResourcesFolderFilePath = Join-Path -Path $resourceModuleRoot -ChildPath "Modules\$helperName\$helperName.psm1"
Import-Module -Name $dscResourcesFolderFilePath

# Import Localization Strings
$script:localizedData = Get-LocalizedData -ResourceName 'PowerShellGet.ResourceHelper' -ScriptRoot $PSScriptRoot

<#
    .SYNOPSIS
        This is a helper function that extract the parameters from a given table.

    .PARAMETER FunctionBoundParameters
        Specifies the hash table containing a set of parameters to be extracted.

    .PARAMETER ArgumentNames
        Specifies a list of arguments you want to extract.
#>
function New-SplatParameterHashTable {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $FunctionBoundParameters,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $ArgumentNames
    )

    Write-Verbose -Message ($script:localizedData.CallingFunction -f $($MyInvocation.MyCommand))

    $returnValue = @{}

    foreach ($arg in $ArgumentNames) {
        if ($FunctionBoundParameters.ContainsKey($arg)) {
            # Found an argument we are looking for, so we add it to return collection.
            $returnValue.Add($arg, $FunctionBoundParameters[$arg])
        }
    }

    return $returnValue
}

<#
    .SYNOPSIS
        This is a helper function that validate that a value is correct and used correctly.

    .PARAMETER Value
        Specifies the value to be validated.

    .PARAMETER Type
        Specifies the type of argument.

    .PARAMETER Type
        Specifies the name of the provider.

    .OUTPUTS
        None. Throws an error if the test fails.
#>
function Test-ParameterValue {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Value,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Type,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ProviderName
    )

    Write-Verbose -Message ($script:localizedData.CallingFunction -f $($MyInvocation.MyCommand))

    switch ($Type) {
        'SourceUri' {
            # Checks whether given URI represents specific scheme
            # Most common schemes: file, http, https, ftp
            $scheme = @('http', 'https', 'file', 'ftp')

            $newUri = $Value -as [System.URI]
            $returnValue = ($newUri -and $newUri.AbsoluteURI -and ($scheme -icontains $newUri.Scheme))

            if ($returnValue -eq $false) {
                $errorMessage = $script:localizedData.InValidUri -f $Value
                New-InvalidArgumentException -ArgumentName $Type -Message $errorMessage
            }
        }

        'DestinationPath' {
            $returnValue = Test-Path -Path $Value

            if ($returnValue -eq $false) {
                $errorMessage = $script:localizedData.PathDoesNotExist -f $Value
                New-InvalidArgumentException -ArgumentName $Type -Message $errorMessage
            }
        }

        <#
        'PackageSource' {
            # Value can be either the package source Name or source Uri.
            # Check if the source is a Uri.
            $uri = $Value -as [System.URI]

            if ($uri -and $uri.AbsoluteURI) {
                # Check if it's a valid Uri.
                Test-ParameterValue -Value $Value -Type 'SourceUri' -ProviderName $ProviderName
            }
            else {
                # Check if it's a registered package source name.
               # $source = PackageManagement\Get-PackageSource -Name $Value -ProviderName $ProviderName -ErrorVariable ev

                if ((-not $source) -or $ev) {
                    # We do not need to throw error here as Get-PackageSource does already.
                    Write-Verbose -Message ($script:localizedData.SourceNotFound -f $source)
                }
            }
        } #>

        default {
            $errorMessage = $script:localizedData.UnexpectedArgument -f $Type
            New-InvalidArgumentException -ArgumentName $Type -Message $errorMessage
        }
    }
}

<#
    .SYNOPSIS
        This is a helper function that does the version validation.

    .PARAMETER Version
        Provides the version.
#>
function Test-VersionParameter {
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        $Version
    )

    Write-Verbose -Message ($localizedData.CallingFunction -f $($MyInvocation.MyCommand))

    $isValid = $false

    # Case 1: No further check required if a user provides either none or one of these: minimumVersion, maximumVersion, and requiredVersion.
    if ($PSBoundParameters.Count -le 1) {
        return $true
    }

        ########## COME BACK HERE
    # Case 2: #If no RequiredVersion is provided.
    #if (-not $PSBoundParameters.ContainsKey('Version')) {
        # If no RequiredVersion, both MinimumVersion and MaximumVersion are provided. Otherwise fall into the Case #1.
        #$isValid = $PSBoundParameters['MinimumVersion'] -le $PSBoundParameters['MaximumVersion']
    #}
    $isValid = $true
    # Case 3: RequiredVersion is provided.
    #        In this case  MinimumVersion and/or MaximumVersion also are provided. Otherwise fall in to Case #1.
    #        This is an invalid case. When RequiredVersion is provided, others are not allowed. so $isValid is false, which is already set in the init.

    if ($isValid -eq $false) {
        $errorMessage = $script:localizedData.VersionError
        New-InvalidArgumentException `
            -ArgumentName 'RequiredVersion, MinimumVersion or MaximumVersion' `
            -Message $errorMessage
    }
}

<#
    .SYNOPSIS
        This is a helper function that retrieves the InstallationPolicy from the given repository.

    .PARAMETER RepositoryName
        Provides the repository Name.
#>
function Get-InstallationPolicy {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String] $RepositoryName
    )

    Write-Verbose -Message ($LocalizedData.CallingFunction -f $($MyInvocation.MyCommand))

    $repositoryObject = Get-PSResourceRepository -Name $RepositoryName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    if ($repositoryObject) {
        return $repositoryObject.IsTrusted
    }
}

<#
    .SYNOPSIS
        This method is used to compare current and desired values for any DSC resource.

    .PARAMETER CurrentValues
        This is hash table of the current values that are applied to the resource.

    .PARAMETER DesiredValues
        This is a PSBoundParametersDictionary of the desired values for the resource.

    .PARAMETER ValuesToCheck
        This is a list of which properties in the desired values list should be checked.
        If this is empty then all values in DesiredValues are checked.
#>
function Test-DscParameterState {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $CurrentValues,

        [Parameter(Mandatory = $true)]
        [System.Object]
        $DesiredValues,

        [Parameter()]
        [System.Array]
        $ValuesToCheck
    )

    $returnValue = $true

    if (($DesiredValues.GetType().Name -ne 'HashTable') `
            -and ($DesiredValues.GetType().Name -ne 'CimInstance') `
            -and ($DesiredValues.GetType().Name -ne 'PSBoundParametersDictionary')) {
        $errorMessage = $script:localizedData.PropertyTypeInvalidForDesiredValues -f $($DesiredValues.GetType().Name)
        New-InvalidArgumentException -ArgumentName 'DesiredValues' -Message $errorMessage
    }

    if (($DesiredValues.GetType().Name -eq 'CimInstance') -and ($null -eq $ValuesToCheck)) {
        $errorMessage = $script:localizedData.PropertyTypeInvalidForValuesToCheck
        New-InvalidArgumentException -ArgumentName 'ValuesToCheck' -Message $errorMessage
    }

    if (($null -eq $ValuesToCheck) -or ($ValuesToCheck.Count -lt 1)) {
        $keyList = $DesiredValues.Keys
    }
    else {
        $keyList = $ValuesToCheck
    }

    $keyList | ForEach-Object -Process {
        if (($_ -ne 'Verbose')) {
            if (($CurrentValues.ContainsKey($_) -eq $false) `
                    -or ($CurrentValues.$_ -ne $DesiredValues.$_) `
                    -or (($DesiredValues.GetType().Name -ne 'CimInstance' -and $DesiredValues.ContainsKey($_) -eq $true) -and ($null -ne $DesiredValues.$_ -and $DesiredValues.$_.GetType().IsArray))) {
                if ($DesiredValues.GetType().Name -eq 'HashTable' -or `
                        $DesiredValues.GetType().Name -eq 'PSBoundParametersDictionary') {
                    $checkDesiredValue = $DesiredValues.ContainsKey($_)
                }
                else {
                    # If DesiredValue is a CimInstance.
                    $checkDesiredValue = $false
                    if (([System.Boolean]($DesiredValues.PSObject.Properties.Name -contains $_)) -eq $true) {
                        if ($null -ne $DesiredValues.$_) {
                            $checkDesiredValue = $true
                        }
                    }
                }

                if ($checkDesiredValue) {
                    $desiredType = $DesiredValues.$_.GetType()
                    $fieldName = $_
                    if ($desiredType.IsArray -eq $true) {
                        if (($CurrentValues.ContainsKey($fieldName) -eq $false) `
                                -or ($null -eq $CurrentValues.$fieldName)) {
                            Write-Verbose -Message ($script:localizedData.PropertyValidationError -f $fieldName) -Verbose

                            $returnValue = $false
                        }
                        else {
                            $arrayCompare = Compare-Object -ReferenceObject $CurrentValues.$fieldName `
                                -DifferenceObject $DesiredValues.$fieldName
                            if ($null -ne $arrayCompare) {
                                Write-Verbose -Message ($script:localizedData.PropertiesDoesNotMatch -f $fieldName) -Verbose

                                $arrayCompare | ForEach-Object -Process {
                                    Write-Verbose -Message ($script:localizedData.PropertyThatDoesNotMatch -f $_.InputObject, $_.SideIndicator) -Verbose
                                }

                                $returnValue = $false
                            }
                        }
                    }
                    else {
                        switch ($desiredType.Name) {
                            'String' {
                                if (-not [System.String]::IsNullOrEmpty($CurrentValues.$fieldName) -or `
                                        -not [System.String]::IsNullOrEmpty($DesiredValues.$fieldName)) {
                                    Write-Verbose -Message ($script:localizedData.ValueOfTypeDoesNotMatch `
                                            -f $desiredType.Name, $fieldName, $($CurrentValues.$fieldName), $($DesiredValues.$fieldName)) -Verbose

                                    $returnValue = $false
                                }
                            }

                            'Int32' {
                                if (-not ($DesiredValues.$fieldName -eq 0) -or `
                                        -not ($null -eq $CurrentValues.$fieldName)) {
                                    Write-Verbose -Message ($script:localizedData.ValueOfTypeDoesNotMatch `
                                            -f $desiredType.Name, $fieldName, $($CurrentValues.$fieldName), $($DesiredValues.$fieldName)) -Verbose

                                    $returnValue = $false
                                }
                            }

                            { $_ -eq 'Int16' -or $_ -eq 'UInt16'} {
                                if (-not ($DesiredValues.$fieldName -eq 0) -or `
                                        -not ($null -eq $CurrentValues.$fieldName)) {
                                    Write-Verbose -Message ($script:localizedData.ValueOfTypeDoesNotMatch `
                                            -f $desiredType.Name, $fieldName, $($CurrentValues.$fieldName), $($DesiredValues.$fieldName)) -Verbose

                                    $returnValue = $false
                                }
                            }

                            default {
                                Write-Warning -Message ($script:localizedData.UnableToCompareProperty `
                                        -f $fieldName, $desiredType.Name)

                                $returnValue = $false
                            }
                        }
                    }
                }
            }
        }
    }

    return $returnValue
}

# SIG # Begin signature block
# MIIjlgYJKoZIhvcNAQcCoIIjhzCCI4MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCTK6d2fPu1MWwQ
# uTNSmUyVKY7PQ9FooOMmYZDlgrgL06CCDYUwggYDMIID66ADAgECAhMzAAABiK9S
# 1rmSbej5AAAAAAGIMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAwMzA0MTgzOTQ4WhcNMjEwMzAzMTgzOTQ4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCSCNryE+Cewy2m4t/a74wZ7C9YTwv1PyC4BvM/kSWPNs8n0RTe+FvYfU+E9uf0
# t7nYlAzHjK+plif2BhD+NgdhIUQ8sVwWO39tjvQRHjP2//vSvIfmmkRoML1Ihnjs
# 9kQiZQzYRDYYRp9xSQYmRwQjk5hl8/U7RgOiQDitVHaU7BT1MI92lfZRuIIDDYBd
# vXtbclYJMVOwqZtv0O9zQCret6R+fRSGaDNfEEpcILL+D7RV3M4uaJE4Ta6KAOdv
# V+MVaJp1YXFTZPKtpjHO6d9pHQPZiG7NdC6QbnRGmsa48uNQrb6AfmLKDI1Lp31W
# MogTaX5tZf+CZT9PSuvjOCLNAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUj9RJL9zNrPcL10RZdMQIXZN7MG8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ1ODM4NjAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# ACnXo8hjp7FeT+H6iQlV3CcGnkSbFvIpKYafgzYCFo3UHY1VHYJVb5jHEO8oG26Q
# qBELmak6MTI+ra3WKMTGhE1sEIlowTcp4IAs8a5wpCh6Vf4Z/bAtIppP3p3gXk2X
# 8UXTc+WxjQYsDkFiSzo/OBa5hkdW1g4EpO43l9mjToBdqEPtIXsZ7Hi1/6y4gK0P
# mMiwG8LMpSn0n/oSHGjrUNBgHJPxgs63Slf58QGBznuXiRaXmfTUDdrvhRocdxIM
# i8nXQwWACMiQzJSRzBP5S2wUq7nMAqjaTbeXhJqD2SFVHdUYlKruvtPSwbnqSRWT
# GI8s4FEXt+TL3w5JnwVZmZkUFoioQDMMjFyaKurdJ6pnzbr1h6QW0R97fWc8xEIz
# LIOiU2rjwWAtlQqFO8KNiykjYGyEf5LyAJKAO+rJd9fsYR+VBauIEQoYmjnUbTXM
# SY2Lf5KMluWlDOGVh8q6XjmBccpaT+8tCfxpaVYPi1ncnwTwaPQvVq8RjWDRB7Pa
# 8ruHgj2HJFi69+hcq7mWx5nTUtzzFa7RSZfE5a1a5AuBmGNRr7f8cNfa01+tiWjV
# Kk1a+gJUBSP0sIxecFbVSXTZ7bqeal45XSDIisZBkWb+83TbXdTGMDSUFKTAdtC+
# r35GfsN8QVy59Hb5ZYzAXczhgRmk7NyE6jD0Ym5TKiW5MIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCFWcwghVjAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAGIr1LWuZJt6PkAAAAA
# AYgwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIjX
# h4N5HTmLXdG6oueU0HPr+Y6X/L1R7I/TrZEeXDTNMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAK4ztLHp4V+fJ45uz8uc+Ua3izZDmxS5cGv3X
# Dy98et+af2tchIiwQIwqU0R0h2gAHbP9G6cABYQkFiXqqQf2LZ0qVoR/ZMUVC8ak
# 84nM3pMS76qdVGEZstGLrayCrfgqMuvYa9YxXzL/6eph1hPKhvJGYZkmSPdKjYCY
# P+XjERh605I3mkzrWvtqDP84uqKbW/fzGEtawGcHw7J04nskqL41Vdtjp7UtqOIR
# IJ3H8mdmhK/h/XERiVcoqDld2+FpPSJWzwZBuRtqhbcrTn6IEf/ucRIcfXnLOSgV
# 3tQ/Vvzyi8AAx6yLoa5KEb9ElyQrNU0tBoZFB/wi4eFdZAcnCKGCEvEwghLtBgor
# BgEEAYI3AwMBMYIS3TCCEtkGCSqGSIb3DQEHAqCCEsowghLGAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFVBgsqhkiG9w0BCRABBKCCAUQEggFAMIIBPAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCCB6+087wvyAlyNx78fS3ybv/c0pAx7x/61
# Uckuyw/1VQIGXzvmTzG0GBMyMDIwMDkwNTA2NDA0My42NTJaMASAAgH0oIHUpIHR
# MIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQL
# EyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046Nzg4MC1FMzkwLTgwMTQxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2Wggg5EMIIE9TCCA92gAwIBAgITMwAAASigDoHhNtVP
# wgAAAAABKDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0xOTEyMTkwMTE1MDBaFw0yMTAzMTcwMTE1MDBaMIHOMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQg
# T3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046
# Nzg4MC1FMzkwLTgwMTQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdkbHW91Tbhj7N
# vw4KXPYLe+yxtCT5A+FVk5RCS5Ks50yZfkaGX4jsDeolnz7uJP5I/J8GO6by7NTr
# AcuPeMrrIOKxy8BzVCT7cNU3OeDDi4HXKLAODcZIu93w8qlsA7YznZOh+5DXMwT6
# gAw+gffKLe+/8EgAgSSMZvagFLnarkuX3MwhdPvmllGrw7uOlN3L+hxIyHVdmXSU
# 1CoOFlCHU2DEFyNPNvqkrOOVgWY3CvfP7SH8fLqvKvJLFhffs1IxkxYjGih4Z+3E
# gqBI+xNbVZltPCEqUuu/FhT9vgNDkMGlnCSjQAivifi2uy89mxrqQonThs+Vw3sH
# NZQ/Zyz3AgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQUhOLyg/F+tTeb1AHDTnR/UATL
# pvIwHwYDVR0jBBgwFoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBL
# oEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
# TWljVGltU3RhUENBXzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggr
# BgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNU
# aW1TdGFQQ0FfMjAxMC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAK
# BggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAQEAi19mRxiFC4A5P4nHB1lMsIw8
# gLAR5YZJrZgaeJZXcC93TaNG12WR4kmQfnNis7z6mOuAZRAo0vz6rq9pvVGk9TdA
# XlKMER0E/PMHc3feIGKil5iw21UfMnlYAZHD/yYlVm13UM3M9REx4Fq4frswPAcF
# IAGhycPp12HHCLg4DyTNVE3jZfUeTr3/us0dhOWSOA6yKr0uIx+ELKDD059uwIze
# 1WbeGpqEcTCxHEAEu7z09SVFGkRaRR5pFGFZZ9WDLMP//+vevGkb8t3JgpUuOLsZ
# JGiC24YdYdPXo2Yx4axJ/pPTHFZFormO9uIyf+e7cpTOwP48yFjY9RfFZYZMsjCC
# BnEwggRZoAMCAQICCmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1
# NVoXDTI1MDcwMTIxNDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/
# aZRrdFQQ1aUKAIKF++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxh
# MFmxMEQP8WCIhFRDDNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhH
# hjKEHnRhZ5FfgVSxz5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tk
# iVBisV39dx898Fd1rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox
# 8NpOBpG2iAg16HgcsOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJN
# AgMBAAGjggHmMIIB4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIox
# kPNDe3xGG8UzaFqFbVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0P
# BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9
# lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQu
# Y29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3Js
# MFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAG
# A1UdIAEB/wSBlTCBkjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAG
# CCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEA
# dABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXED
# PZ2joSFvs+umzPUxvs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgr
# UYJEEvu5U4zM9GASinbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c
# 8pl5SpFSAK84Dxf1L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFw
# nzJKJ/1Vry/+tuWOM7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFt
# w5yjojz6f32WapB4pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk
# 7Pf0v35jWSUPei45V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9d
# dJgiCGHasFAeb73x4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zG
# y9iCtHLNHfS4hQEegPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3
# yKxO2ii4sanblrKnQqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7c
# RDyXUHHXodLFVeNp3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wkn
# HNWzfjUeCLraNtvTX4/edIhJEqGCAtIwggI7AgEBMIH8oYHUpIHRMIHOMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3Nv
# ZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046Nzg4MC1FMzkwLTgwMTQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVADE9SxvygBI9F7Ii/Z+5sZl9Wn2boIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDi/XYkMCIYDzIwMjAwOTA1MDYyNzQ4WhgPMjAyMDA5MDYwNjI3NDhaMHcw
# PQYKKwYBBAGEWQoEATEvMC0wCgIFAOL9diQCAQAwCgIBAAICEUsCAf8wBwIBAAIC
# EYUwCgIFAOL+x6QCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAK
# MAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBOmzee0UXO
# 8U+HE1mvoVPvaspKxIkhKhkV+R4Dao0Y5OZpogn/tex0CrP6Ni62h7ZiFNF8w4qV
# wLeTCc5U5P+cpt1kpOPzhz5dtOYfjDa4EviwFXWGky1SZ9culxOWO/q+Dr5F1BIA
# 1S3lu2UDIHqINjwGUZPrRfMR/2VgiNBu8zGCAw0wggMJAgEBMIGTMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABKKAOgeE21U/CAAAAAAEoMA0GCWCG
# SAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZI
# hvcNAQkEMSIEIMoc3DwgdVOwPOnWObyBrVm9VoOP2KYu7/AjpzawhFRVMIH6Bgsq
# hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgvEVqi68FUnfv3BsQ3wakuG9bT14aDxaw
# uteb1dboFNowgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAIT
# MwAAASigDoHhNtVPwgAAAAABKDAiBCAsAJMdbTVxYbmDfl545epAX8IIqyza8nB7
# WhfJ3y384jANBgkqhkiG9w0BAQsFAASCAQBSlLT5spLhI6ghOYKRvh1WukH1XT24
# 6FMkI5xUXq2nmnzxaldpiHhL6T99bHBdBykn79k6bh9L/l8AWDeJpHO1ZrNZdhAw
# Gj1PjlmtOA1qDXXEfrnbmMw77quLsZxuIM5Gc6PFFyepePDK10dmKEeLRy20Bzvb
# wB1mO0tOhQQ6PJMOP+P43K5/yVEX9ECdiOX00rfBA4AbBcLSy3l3d/hx5O82MYYJ
# PZx78NduBm2RURHwMcMhhezTV7n1QmvSCE6HLZhzPvIN+7Zis8Hn/eTyEYw5bOyM
# 39npQgNaio5JngJ4HuQrWqj5LcdKYEiYoC5AdH4C4TPlRY/5zSoAd4gl
# SIG # End signature block
