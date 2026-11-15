$utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8

$engineIdentity = "WindowsPowerShell/$($PSVersionTable.PSVersion.ToString())/$($PSVersionTable.PSEdition)"
$hardNodeLimit = 100000
$hardDepthLimit = 512
$hardUnitLimit = 256

function New-Reply {
  param(
    [string]$RequestId,
    [string]$Completeness,
    [object[]]$ParseErrors,
    [object[]]$Units,
    [object[]]$ProgramCalls,
    [object[]]$LanguageOperations,
    [string[]]$Features,
    [int]$AstNodeCount,
    [int]$MaxDepth
  )

  return @{
    protocolVersion = 1
    requestId = $RequestId
    engineIdentity = $engineIdentity
    completeness = $Completeness
    parseErrors = $ParseErrors
    units = $Units
    programCalls = $ProgramCalls
    languageOperations = $LanguageOperations
    features = $Features
    astNodeCount = $AstNodeCount
    maxDepth = $MaxDepth
  }
}

function Get-StaticArgument {
  param([System.Management.Automation.Language.Ast]$Element)

  if ($Element -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
    return @{ known = $true; value = $Element.Value }
  }
  if ($Element -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and
      $Element.NestedExpressions.Count -eq 0) {
    return @{ known = $true; value = $Element.Value }
  }
  if ($Element -is [System.Management.Automation.Language.CommandParameterAst]) {
    $value = "-$($Element.ParameterName)"
    if ($Element.Argument -ne $null) {
      $argument = Get-StaticArgument $Element.Argument
      if (-not $argument.known) { return @{ known = $false; value = $null } }
      $value += ":$($argument.value)"
    }
    return @{ known = $true; value = $value }
  }
  return @{ known = $false; value = $null }
}

function Get-StaticCommandTarget {
  param(
    [System.Management.Automation.Language.CommandAst]$Command,
    [string[]]$Parameters,
    [int]$PositionalIndex = 0
  )

  $parameterNames = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
  foreach ($parameter in $Parameters) { [void]$parameterNames.Add($parameter) }
  for ($index = 1; $index -lt $Command.CommandElements.Count; $index++) {
    $element = $Command.CommandElements[$index]
    if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
      if (-not $parameterNames.Contains($element.ParameterName)) { continue }
      if ($element.Argument -ne $null) {
        $argument = Get-StaticArgument $element.Argument
        if ($argument.known) { return [string]$argument.value }
        return $null
      }
      if ($index + 1 -lt $Command.CommandElements.Count) {
        $argument = Get-StaticArgument $Command.CommandElements[$index + 1]
        if ($argument.known) { return [string]$argument.value }
      }
      return $null
    }
  }

  $position = 0
  for ($index = 1; $index -lt $Command.CommandElements.Count; $index++) {
    $element = $Command.CommandElements[$index]
    if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
      if ($element.Argument -ne $null) { $index++ }
      continue
    }
    if ($position -eq $PositionalIndex) {
      $argument = Get-StaticArgument $element
      if ($argument.known) { return [string]$argument.value }
      return $null
    }
    $position++
  }
  return $null
}

function Get-AstDepth {
  param([System.Management.Automation.Language.Ast]$Node)

  $depth = 0
  $parent = $Node.Parent
  while ($parent -ne $null) {
    $depth++
    $parent = $parent.Parent
  }
  return $depth
}

function Add-LanguageOperation {
  param(
    [string]$Kind,
    [System.Management.Automation.Language.Ast]$Node,
    [AllowNull()][object]$Target = $null
  )

  [void]$script:features.Add($Kind)
  [void]$script:languageOperations.Add(@{
    kind = $Kind
    start = [int]$Node.Extent.StartOffset
    end = [int]$Node.Extent.EndOffset
    target = $Target
  })
}

while ($null -ne ($line = [Console]::In.ReadLine())) {
  $requestId = ""
  try {
    $request = ConvertFrom-Json -InputObject $line -ErrorAction Stop
    if ($null -ne $request.requestId -and $request.requestId -is [string]) {
      $requestId = $request.requestId
    }
    if ($request.protocolVersion -ne 1 -or $request.source -isnot [string] -or
        $request.limits -eq $null) {
      throw "invalid-request"
    }

    $maxAstNodes = [Math]::Min($hardNodeLimit, [int]$request.limits.maxAstNodes)
    $maxDepth = [Math]::Min($hardDepthLimit, [int]$request.limits.maxDepth)
    $maxUnits = [Math]::Min($hardUnitLimit, [int]$request.limits.maxUnits)
    if ($maxAstNodes -lt 1 -or $maxDepth -lt 1 -or $maxUnits -lt 1) {
      throw "invalid-limits"
    }

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
      $request.source,
      [ref]$tokens,
      [ref]$errors
    )
    $parseErrors = @()
    foreach ($error in $errors) {
      $parseErrors += @{
        id = [string]$error.ErrorId
        start = [int]$error.Extent.StartOffset
        end = [int]$error.Extent.EndOffset
      }
    }

    $nodeCount = 0
    $observedDepth = 0
    $limitExceeded = $false
    foreach ($node in $ast.FindAll({ param($candidate) $true }, $true)) {
      $nodeCount++
      if ($nodeCount -gt $maxAstNodes) {
        $limitExceeded = $true
        break
      }
      $depth = Get-AstDepth $node
      if ($depth -gt $observedDepth) { $observedDepth = $depth }
      if ($depth -gt $maxDepth) {
        $limitExceeded = $true
        break
      }
    }

    $statements = @()
    if ($null -ne $ast.EndBlock) { $statements = @($ast.EndBlock.Statements) }
    if ($statements.Count -gt $maxUnits) { $limitExceeded = $true }
    if ($parseErrors.Count -gt 0 -or $limitExceeded) {
      $reply = New-Reply -RequestId $requestId -Completeness "failed" -ParseErrors $parseErrors `
        -Units @() -ProgramCalls @() -LanguageOperations @() -Features @() `
        -AstNodeCount $nodeCount -MaxDepth $observedDepth
    } else {
      $units = @()
      foreach ($statement in $statements) {
        $units += @{
          start = [int]$statement.Extent.StartOffset
          end = [int]$statement.Extent.EndOffset
        }
      }

      $programCalls = @()
      $script:languageOperations = New-Object System.Collections.Generic.List[object]
      $script:features = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::Ordinal)
      $commands = $ast.FindAll({ param($candidate)
        $candidate -is [System.Management.Automation.Language.CommandAst]
      }, $true)
      foreach ($command in $commands) {
        $commandName = $command.GetCommandName()
        $arguments = @()
        $argumentsKnown = $command.CommandElements.Count -gt 0
        for ($index = 1; $index -lt $command.CommandElements.Count; $index++) {
          $argument = Get-StaticArgument $command.CommandElements[$index]
          if (-not $argument.known) {
            $argumentsKnown = $false
            break
          }
          $arguments += [string]$argument.value
        }
        $dotSource = $command.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot
        $dynamic = ($null -eq $commandName) -or $dotSource
        $argumentOutput = $null
        if ($argumentsKnown) { $argumentOutput = [object[]]$arguments }
        if ($dotSource) { Add-LanguageOperation "dot-source" $command }
        if ($null -eq $commandName) { Add-LanguageOperation "dynamic-command" $command }
        if (-not $argumentsKnown) { Add-LanguageOperation "dynamic-argument" $command }
        if ($commandName -match '^(?i:Start-Process|Start-Job|Invoke-Command|pwsh|powershell|cmd|cmd\.exe)$') {
          Add-LanguageOperation "process-spawn" $command
        }
        if ($commandName -match '^(?i:Set-Location|Push-Location|Pop-Location|cd|chdir|sl|pushd|popd)$') {
          $target = if ($commandName -match '^(?i:Pop-Location|popd)$') { $null } else {
            Get-StaticCommandTarget $command @("Path", "LiteralPath") 0
          }
          Add-LanguageOperation "location-change" $command $target
        }
        if ($commandName -match '^(?i:Set-Alias|New-Alias|Remove-Alias)$') {
          Add-LanguageOperation "alias-change" $command
        }
        if ($commandName -match '^(?i:Copy-Item|Move-Item)$') {
          $source = Get-StaticCommandTarget $command @("Path", "LiteralPath") 0
          $destination = Get-StaticCommandTarget $command @("Destination", "DestinationPath") 1
          if ($commandName -match '^(?i:Copy-Item)$') {
            Add-LanguageOperation "file-read" $command $source
          } else {
            Add-LanguageOperation "file-delete" $command $source
          }
          Add-LanguageOperation "file-write" $command $destination
        }
        if ($commandName -match '^(?i:Set-Content|Add-Content|Clear-Content|Out-File|Export-Csv|Set-Item|New-Item)$') {
          $target = Get-StaticCommandTarget $command @("Path", "LiteralPath", "FilePath") 0
          Add-LanguageOperation "file-write" $command $target
        }
        if ($commandName -match '^(?i:Remove-Item|rm|del|erase|rd|rmdir)$') {
          $target = Get-StaticCommandTarget $command @("Path", "LiteralPath", "Name") 0
          Add-LanguageOperation "file-delete" $command $target
        }
        if ($commandName -match '^(?i:Get-Content|Get-ChildItem|Get-Item|Test-Path|Get-ItemProperty|gci|dir|ls)$') {
          $target = Get-StaticCommandTarget $command @("Path", "LiteralPath", "Name") 0
          if ($null -eq $target -and $commandName -match '^(?i:Get-ChildItem|gci|dir|ls)$' -and $command.CommandElements.Count -eq 1) {
            $target = "."
          }
          Add-LanguageOperation "file-read" $command $target
        }
        if ($commandName -match '^(?i:Invoke-WebRequest|Invoke-RestMethod)$') {
          $target = Get-StaticCommandTarget $command @("Uri", "Url") 0
          Add-LanguageOperation "network-access" $command $target
        }
        if ($commandName -match '^(?i:Clear-Item|Remove-ItemProperty|Set-ItemProperty|New-ItemProperty)$') {
          Add-LanguageOperation "provider-access" $command
        }
        if ($commandName -match '^(?i:Invoke-Expression|IEX|ScriptBlock\.Create)$') {
          Add-LanguageOperation "dynamic-execution" $command
        }
        if ($arguments -match '^(?i:(HKLM|HKCU|HKCR|HKU|HKCC|Registry|Cert|Env|Alias|Function|Variable|WSMan):|Registry::)') {
          Add-LanguageOperation "provider-access" $command
        }
        if ($commandName -match '^(?i:pwsh|powershell|cmd|cmd\.exe)$' -and
            ($arguments -match '^(?i:-c|-command|-enc|-encodedcommand|/c)$')) {
          Add-LanguageOperation "dynamic-execution" $command
        }
        $programCalls += @{
          start = [int]$command.Extent.StartOffset
          end = [int]$command.Extent.EndOffset
          commandName = if ($null -eq $commandName) { $null } else { [string]$commandName }
          arguments = $argumentOutput
          dynamic = [bool]$dynamic
          dotSource = [bool]$dotSource
        }
      }
      foreach ($node in $ast.FindAll({ param($candidate) $true }, $true)) {
        if ($node -is [System.Management.Automation.Language.AssignmentStatementAst]) {
          if ($node.Left.Extent.Text -match '^\s*\$[\w]*:env:') {
            Add-LanguageOperation "environment-change" $node
          } else {
            Add-LanguageOperation "assignment" $node
          }
        } elseif ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
          Add-LanguageOperation "function-definition" $node
        } elseif ($node -is [System.Management.Automation.Language.IfStatementAst] -or
                  $node -is [System.Management.Automation.Language.LoopStatementAst] -or
                  $node -is [System.Management.Automation.Language.SwitchStatementAst] -or
                  $node -is [System.Management.Automation.Language.TryStatementAst] -or
                  $node -is [System.Management.Automation.Language.TrapStatementAst]) {
          Add-LanguageOperation "control-flow" $node
        } elseif ($node -is [System.Management.Automation.Language.FileRedirectionAst]) {
          $target = Get-StaticArgument $node.Location
          Add-LanguageOperation "redirection" $node $(if ($target.known) { [string]$target.value } else { $null })
        } elseif ($node -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
          Add-LanguageOperation "dynamic-execution" $node
        } elseif ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
          Add-LanguageOperation "unknown" $node
        } elseif ($node -is [System.Management.Automation.Language.VariableExpressionAst] -and $node.Splatted) {
          Add-LanguageOperation "dynamic-argument" $node
        }
      }
      $featureArray = @()
      foreach ($feature in $script:features) { $featureArray += [string]$feature }
      $languageOperationArray = $script:languageOperations.ToArray()
      $reply = New-Reply -RequestId $requestId -Completeness "complete" -ParseErrors @() `
        -Units $units -ProgramCalls $programCalls -LanguageOperations $languageOperationArray `
        -Features $featureArray -AstNodeCount $nodeCount -MaxDepth $observedDepth
    }
  } catch {
    $reply = New-Reply -RequestId $requestId -Completeness "failed" -ParseErrors @() `
      -Units @() -ProgramCalls @() -LanguageOperations @() -Features @() `
      -AstNodeCount 0 -MaxDepth 0
  }

  $json = ConvertTo-Json -InputObject $reply -Compress -Depth 8
  [Console]::Out.WriteLine($json)
}
