_ssm_cli_completions()
{
    local cur prev words cword
    _init_completion || return

    local commands="user secret kek cache-stats audit-log backup db export tui env server help"
    local user_sub="register auth delete change-password"
    local secret_sub="store get delete list"
    local kek_sub="rotate"
    local backup_sub="create restore"
    local db_sub="version migrate"
    local env_sub="exec"
    local server_sub="start"

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        return
    fi

    local prev_cmd="${words[1]}"

    case $prev_cmd in
        user)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "$user_sub" -- "$cur"))
            fi
            ;;
        secret)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "$secret_sub" -- "$cur"))
            elif [[ $cword -ge 3 ]] && [[ "${words[2]}" == "store" ]]; then
                if [[ "$prev" == "--pub" ]] || [[ "$prev" == "--desc" ]]; then
                    return
                fi
                COMPREPLY=($(compgen -W "--pub --desc" -- "$cur"))
            elif [[ $cword -ge 3 ]] && [[ "${words[2]}" == "get" ]]; then
                if [[ "$prev" == "--out" ]] || [[ "$prev" == "--pub-out" ]]; then
                    COMPREPLY=($(compgen -f -- "$cur"))
                else
                    COMPREPLY=($(compgen -W "--out --pub-out" -- "$cur"))
                fi
            fi
            ;;
        kek)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "$kek_sub" -- "$cur"))
            fi
            ;;
        backup)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "$backup_sub" -- "$cur"))
            elif [[ $cword -eq 3 ]]; then
                COMPREPLY=($(compgen -f -- "$cur"))
            fi
            ;;
        db)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "$db_sub" -- "$cur"))
            fi
            ;;
        env)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "$env_sub" -- "$cur"))
            fi
            ;;
        server)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "$server_sub" -- "$cur"))
            elif [[ $cword -ge 3 ]]; then
                COMPREPLY=($(compgen -W "--port --host --daemonize --pidfile" -- "$cur"))
            fi
            ;;
        audit-log)
            if [[ $cword -ge 2 ]]; then
                COMPREPLY=($(compgen -W "--operation --result --limit --offset" -- "$cur"))
            fi
            ;;
        export)
            if [[ $cword -ge 2 ]]; then
                COMPREPLY=($(compgen -W "--format --redact-pii" -- "$cur"))
            fi
            ;;
    esac

    if [[ $cword -ge 2 ]] && [[ "$prev" == "--db" || "$prev" == "--db-key" || "$prev" == "--password" || "$prev" == "--backup-key" ]]; then
        return
    fi

    if [[ $cword -ge 1 ]] && [[ "$prev" == "--format" ]]; then
        COMPREPLY=($(compgen -W "json csv" -- "$cur"))
        return
    fi

    local global_opts="--db --db-key --password --backup-key --json --help --version"
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$commands $global_opts" -- "$cur"))
    fi
}

complete -F _ssm_cli_completions ssm-cli
