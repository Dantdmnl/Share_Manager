@{
    # Customize PSScriptAnalyzer rules for this interactive CLI/GUI script
    # We intentionally use Write-Host for colored, interactive output and
    # have internal state-changing helpers that aren't intended as public cmdlets.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns',
        'PSAvoidTrailingWhitespace'
    )
}
