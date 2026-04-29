# Enumerate AD users in a target OU with default properties + MemberOf

#Requires -Modules ActiveDirectory

param(
    [Parameter(Mandatory)]
    [string]$SearchBase,

    [ValidateSet('Base', 'OneLevel', 'Subtree')]
    [string]$SearchScope = 'Subtree'
)

Get-ADUser -Filter * -SearchBase $SearchBase -SearchScope $SearchScope -Properties MemberOf |
    Select-Object DistinguishedName, Enabled, GivenName, Name, ObjectClass,
                  ObjectGUID, SamAccountName, SID, Surname, UserPrincipalName,
                  @{Name = 'MemberOf'; Expression = { $_.MemberOf -join '; ' }}