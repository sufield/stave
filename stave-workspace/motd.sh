#!/bin/sh
# Message-of-the-day for the Stave adopter workspace.
# Sourced by /etc/profile on every interactive shell — keep it
# quiet (no errors, no slow commands) so it doesn't drag terminal
# launches.
#
# Skip on non-interactive shells (Coder runs build/test commands
# that don't want a banner spammed into their output).
case $- in *i*) ;; *) return 0 ;; esac

printf '\n'
printf '  \033[1mStave Security Evaluation Workspace\033[0m\n'
printf '\n'
printf '  Quick start:\n'
printf '    bash ~/examples/demo-ai-security/run.sh\n'
printf '\n'
printf '  Visualizers:\n'
printf '    stave-mcp --demo-dashboard    --observations ~/examples/demo-ai-security/obs\n'
printf '    stave-mcp --render-scorecard  --observations ~/examples/demo-ai-security/obs --frameworks hipaa\n'
printf '    stave-mcp --render-chains     --observations ~/examples/demo-ai-security/obs\n'
printf '\n'
printf '  Guides:    ls ~/guides/        (see also: cat ~/guides/START-HERE.md)\n'
printf '\n'
