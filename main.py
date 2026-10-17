#!/usr/bin/env python3
"""Entry point for SecureMySite security analyzer."""

import sys
import argparse
import logging
from pathlib import Path

from app import Application, setup_logging
from core.config import APP_VERSION


SEVERITY_CHOICES = ['critical', 'high', 'medium', 'low']
EXPORT_CHOICES = ['json', 'html', 'markdown', 'sarif', 'csv']
EXTENSION_FORMATS = {'.json': 'json', '.html': 'html', '.htm': 'html', '.md': 'markdown',
                     '.markdown': 'markdown', '.sarif': 'sarif', '.csv': 'csv'}


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        prog='securemysite',
        description='Secure My Site - Local security analyzer for AI-generated web projects',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                   Launch GUI mode
  %(prog)s ./project                         Scan project in CLI mode
  %(prog)s ./project --url http://localhost:8000
                                             Also scan the running app
  %(prog)s ./project -o report.html          Export (format from extension)
  %(prog)s ./project -e sarif -o results.sarif --fail-on high
                                             CI usage (GitHub code scanning)
  %(prog)s ./project -o baseline.json        Save a baseline ...
  %(prog)s ./project --baseline baseline.json
                                             ... then only report new findings
  %(prog)s ./project --prompt                Generate AI fix prompt
  %(prog)s --domain example.com              Online check of a live domain
  %(prog)s --domain mysite.com --active --authorized
                                             ...plus exposed-file probing (your own sites only)

Exit codes (default): 0 = no high/critical, 1 = high found, 2 = critical found, 3 = scan error.
With --fail-on LEVEL: 1 if any finding at or above LEVEL, else 0.

Suppress a finding by adding "securemysite: ignore" (or "nosec") in a comment on that line,
or list paths to skip in a .securemysiteignore file in the project root.
        """
    )

    parser.add_argument('project_path', nargs='?', type=Path, help='Path to project directory to scan')

    parser.add_argument('--url', '-u', type=str, metavar='URL',
                        help='Local URL for web scanning (e.g., http://localhost:8000)')

    parser.add_argument('--domain', '-d', type=str, metavar='DOMAIN',
                        help='Online scan of a public domain: DNS/DNSSEC, SPF/DMARC, WHOIS, TLS, website headers')

    parser.add_argument('--active', action='store_true',
                        help='Domain scan: also probe for exposed files (/.env, /.git, ...). Requires --authorized')

    parser.add_argument('--authorized', action='store_true',
                        help='Confirm you own or are authorized to security-test the --domain target')

    parser.add_argument('--export', '-e', choices=EXPORT_CHOICES, metavar='FORMAT',
                        help=f'Export format: {", ".join(EXPORT_CHOICES)} (default: from --output extension)')

    parser.add_argument('--output', '-o', type=str, metavar='PATH',
                        help='Output file for export ("-" for stdout)')

    parser.add_argument('--prompt', '-p', action='store_true', help='Generate AI fix prompt')

    parser.add_argument('--fail-on', choices=SEVERITY_CHOICES + ['none'], metavar='LEVEL',
                        help='Exit with code 1 if findings at/above LEVEL exist (critical, high, medium, low, none)')

    parser.add_argument('--min-severity', choices=SEVERITY_CHOICES, metavar='LEVEL',
                        help='Only report findings at or above this severity')

    parser.add_argument('--baseline', type=Path, metavar='REPORT.json',
                        help='Hide findings already present in a previous JSON report')

    parser.add_argument('--exclude', action='append', default=[], metavar='GLOB',
                        help='Skip paths matching GLOB (repeatable), e.g. --exclude "migrations/*"')

    parser.add_argument('--scanners', type=str, metavar='LIST',
                        help='Comma-separated scanners to run (see --list-scanners)')

    parser.add_argument('--list-scanners', action='store_true', help='List available scanners and exit')

    parser.add_argument('--online', action='store_true',
                        help='Also query OSV.dev for dependency vulnerabilities (sends package names/versions)')

    parser.add_argument('--quiet', '-q', action='store_true', help='Only print the summary line')

    parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')

    parser.add_argument('--version', action='version', version=f'%(prog)s {APP_VERSION}')

    return parser


def validate_args(args: argparse.Namespace) -> bool:
    """Validate command line arguments."""
    if args.project_path:
        if not args.project_path.exists():
            print(f"Error: Project path does not exist: {args.project_path}", file=sys.stderr)
            return False
        if not args.project_path.is_dir():
            print(f"Error: Project path is not a directory: {args.project_path}", file=sys.stderr)
            return False

    if args.url:
        from utils.validators import validate_url
        is_valid, error = validate_url(args.url)
        if not is_valid:
            print(f"Error: {error}", file=sys.stderr)
            return False

    if args.export and not args.output:
        print("Error: --output required when using --export (use '-o -' for stdout)", file=sys.stderr)
        return False

    if args.output and not args.export:
        fmt = EXTENSION_FORMATS.get(Path(args.output).suffix.lower()) if args.output != '-' else None
        if not fmt:
            print("Error: cannot infer export format from --output; pass --export", file=sys.stderr)
            return False
        args.export = fmt

    if args.baseline and not args.baseline.is_file():
        print(f"Error: baseline file not found: {args.baseline}", file=sys.stderr)
        return False

    if args.scanners:
        from core.engine import AnalysisEngine
        unknown = [s for s in args.scanners.split(',') if s.strip() not in AnalysisEngine.SCANNER_REGISTRY]
        if unknown:
            print(f"Error: unknown scanner(s): {', '.join(unknown)}. Use --list-scanners.", file=sys.stderr)
            return False

    if args.domain:
        if args.project_path:
            print("Error: use either a project path or --domain, not both", file=sys.stderr)
            return False
        from utils.validators import normalize_domain
        host, error = normalize_domain(args.domain)
        if not host:
            print(f"Error: {error}", file=sys.stderr)
            return False
        if args.active and not args.authorized:
            print("Error: --active sends probing requests; add --authorized to confirm you own or are "
                  "authorized to test this domain", file=sys.stderr)
            return False
        if args.baseline or args.url:
            print("Error: --baseline and --url are not supported with --domain", file=sys.stderr)
            return False
        return True

    if args.active:
        print("Error: --active only applies to --domain scans", file=sys.stderr)
        return False

    if (args.export or args.prompt or args.fail_on or args.baseline) and not args.project_path:
        print("Error: a project path is required for CLI options", file=sys.stderr)
        return False

    return True


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    setup_logging(verbose=args.verbose, cli=bool(args.project_path or args.domain))
    logger = logging.getLogger(__name__)
    logger.debug(f"Arguments: {args}")

    if args.list_scanners:
        from core.engine import AnalysisEngine
        from core.config import Config
        for name, description in AnalysisEngine.available_scanners().items():
            default = '*' if name in Config.DEFAULT_SCANNERS else ' '
            print(f" {default} {name:<20} {description}")
        print("\n * = enabled by default (web_scanner runs when --url is given)")
        return 0

    if not validate_args(args):
        return 3

    app = Application()

    if args.domain:
        return app.run_domain(
            domain=args.domain,
            active=args.active,
            export_format=args.export,
            export_path=args.output,
            generate_prompt=args.prompt,
            fail_on=args.fail_on,
            min_severity=args.min_severity,
            quiet=args.quiet,
            color=not args.no_color,
        )

    if args.project_path:
        return app.run_cli(
            project_path=args.project_path,
            url=args.url,
            export_format=args.export,
            export_path=args.output,
            generate_prompt=args.prompt,
            fail_on=args.fail_on,
            min_severity=args.min_severity,
            baseline=args.baseline,
            excludes=args.exclude,
            scanners=[s.strip() for s in args.scanners.split(',')] if args.scanners else None,
            online=args.online,
            quiet=args.quiet,
            color=not args.no_color,
        )
    return app.run_gui()


if __name__ == '__main__':
    sys.exit(main())
