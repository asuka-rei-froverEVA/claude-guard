BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\..\src\ClaudeGuard\ClaudeGuard.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
}

Describe 'Windows path policy' {
    It 'treats drive and slash spelling differences as the same path identity' {
        $filePath = Join-Path $TestDrive 'Client.EXE'
        'fixture' | Set-Content -LiteralPath $filePath
        $alternate = $filePath.ToLowerInvariant().Replace('\', '/')

        InModuleScope ClaudeGuard -Parameters @{ Left = $filePath; Right = $alternate } {
            Test-GuardPathIdentity -Left $Left -Right $Right | Should -BeTrue
        }
    }

    It 'returns a normalized absolute regular-file path' {
        $filePath = Join-Path $TestDrive 'client.exe'
        'fixture' | Set-Content -LiteralPath $filePath

        InModuleScope ClaudeGuard -Parameters @{ FilePath = $filePath } {
            $resolved = Resolve-GuardPath -Path $FilePath -Kind File

            $resolved.Result.status | Should -BeExactly 'pass'
            $resolved.Path | Should -BeExactly (Get-Item -LiteralPath $FilePath).FullName
            $resolved.IsReparsePoint | Should -BeFalse
        }
    }

    It 'rejects a directory when a regular file is required' {
        $directoryPath = Join-Path $TestDrive 'directory'
        New-Item -ItemType Directory -Path $directoryPath | Out-Null

        InModuleScope ClaudeGuard -Parameters @{ DirectoryPath = $directoryPath } {
            $resolved = Resolve-GuardPath -Path $DirectoryPath -Kind File

            $resolved.Result.code | Should -BeExactly 'CG_PATH_KIND_INVALID'
            $resolved.Result.exit_code | Should -Be 2
        }
    }

    It 'detects reparse points using filesystem metadata' {
        $targetPath = Join-Path $TestDrive 'target'
        $junctionPath = Join-Path $TestDrive 'junction'
        New-Item -ItemType Directory -Path $targetPath | Out-Null
        New-Item -ItemType Junction -Path $junctionPath -Target $targetPath | Out-Null

        InModuleScope ClaudeGuard -Parameters @{ JunctionPath = $junctionPath } {
            $resolved = Resolve-GuardPath `
                -Path $JunctionPath `
                -Kind Directory `
                -RejectReparsePoint

            $resolved.IsReparsePoint | Should -BeTrue
            $resolved.Result.code | Should -BeExactly 'CG_PATH_REPARSE_POINT'
        }
    }
}
