#compdef ssm-cli

_ssm_cli_zsh_completions()
{
    local -a commands
    commands=(
        'user:Manage users (register, auth, delete, change-password)'
        'secret:Manage secrets (store, get, delete, list)'
        'kek:KEK operations (rotate)'
        'cache-stats:Show cache statistics'
        'audit-log:Query audit log'
        'backup:Create or restore encrypted backup'
        'db:Database schema version and migration'
        'export:Export metadata (JSON/CSV)'
        'tui:Interactive terminal interface'
        'env:Execute command with secrets as env vars'
        'server:Start REST API server'
        'help:Show help'
    )

    local -a user_sub
    user_sub=('register:Register new user' 'auth:Verify credentials' 'delete:Delete user' 'change-password:Change password')

    local -a secret_sub
    secret_sub=('store:Store a secret' 'get:Get a secret' 'delete:Delete a secret' 'list:List secrets')

    _arguments -C \
        '--db[SQLite database path]:database file:_files' \
        '--db-key[SQLCipher hex key]:hex key' \
        '--password[Password for operations]:password' \
        '--backup-key[64 hex chars backup key]:hex key' \
        '--json[Machine-readable JSON output]' \
        '--help[Show help]' \
        '--version[Show version]' \
        '1:command:->cmds' \
        '*::args:->args'

    case $state in
        cmds)
            _describe -t commands 'ssm-cli command' commands
            ;;
        args)
            case $words[1] in
                user)
                    _describe -t sub 'user subcommand' user_sub
                    ;;
                secret)
                    if [[ $CURRENT -eq 3 ]]; then
                        _describe -t sub 'secret subcommand' secret_sub
                    elif [[ $words[2] == "store" ]]; then
                        _arguments '--pub[Public key file]:public key file:_files' '--desc[Description]:description'
                    elif [[ $words[2] == "get" ]]; then
                        _arguments '--out[Output file]:output file:_files' '--pub-out[Public key output]:public key output:_files'
                    fi
                    ;;
                kek)
                    _arguments '1: :(rotate)'
                    ;;
                backup)
                    if [[ $CURRENT -eq 3 ]]; then
                        _arguments '1: :(create restore)'
                    else
                        _arguments '*:backup file:_files'
                    fi
                    ;;
                db)
                    _arguments '1: :(version migrate)'
                    ;;
                env)
                    if [[ $CURRENT -eq 3 ]]; then
                        _arguments '1: :(exec)'
                    fi
                    ;;
                server)
                    if [[ $CURRENT -eq 3 ]]; then
                        _arguments '1: :(start)'
                    else
                        _arguments '--port[Port number]' '--host[Host address]' '--daemonize[Run as daemon]' '--pidfile[PID file]:pid file:_files'
                    fi
                    ;;
                export)
                    _arguments '--format[Output format]:format:(json csv)' '--redact-pii[Redact personal info]'
                    ;;
                audit-log)
                    _arguments '--operation[Filter by operation]' '--result[Filter by result]' '--limit[Max results]' '--offset[Offset]'
                    ;;
            esac
            ;;
    esac
}

_ssm_cli_zsh_completions "$@"
