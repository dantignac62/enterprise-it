@{
    # Rules intentionally excluded for this codebase. The static-analysis test
    # gates on Error-severity findings; these two rules are design choices, not
    # defects, and would otherwise drown the report in expected noise.
    ExcludeRules = @(
        # These are operator-facing console tools; colored Write-Host status
        # output is the intended UX (the library funnels it through Write-Log).
        'PSAvoidUsingWriteHost',

        # The snapshot/registry readback helpers are documented as best-effort:
        # a missing cmdlet on an older image must never abort a hardening run,
        # so they deliberately swallow in empty catch blocks.
        'PSAvoidUsingEmptyCatchBlock'
    )
}
