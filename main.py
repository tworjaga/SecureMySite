#!/usr/bin/env python3
"""Entry point for SecureMySite security analyzer."""

import sys
import argparse
import logging
from pathlib import Path

from app import Application, setup_logging


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        prog='securemysite',
        description='Secure My Site - Local security analyzer for AI-generated web projects',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Launch GUI mode
  %(prog)s /path/to/project         Scan project in CLI mode
  %(prog)s /path/to/project --url http://localhost:8000
                                    Scan with web analysis
  %(prog)s /path/to/project --export json --output report.json
                                    Export results to JSON
  %(prog)s /path/to/project --prompt
                                    Generate AI fix prompt
        """
    )
    
    parser.add_argument(
        'project_path',
        nargs='?',
        type=Path,
        help='Path to project directory to scan'
    )
    
    parser.add_argument(
        '--url', '-u',
        type=str,
        metavar='URL',
        help='Local URL for web scanning (e.g., http://localhost:8000)'
    )
    
    parser.add_argument(
        '--export', '-e',
        choices=['json', 'html', 'markdown'],
        metavar='FORMAT',
        help='Export format for results'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=Path,
        metavar='PATH',
        help='Output file path for export'
    )
    
    parser.add_argument(
        '--prompt', '-p',
        action='store_true',
        help='Generate AI fix prompt'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    return parser


def validate_args(args: argparse.Namespace) -> bool:
    """Validate command line arguments."""
    # If project path provided, validate it
    if args.project_path:
        if not args.project_path.exists():
            print(f"Error: Project path does not exist: {args.project_path}", file=sys.stderr)
            return False
        
        if not args.project_path.is_dir():
            print(f"Error: Project path is not a directory: {args.project_path}", file=sys.stderr)
            return False
    
    # Validate URL if provided
    if args.url:
        from utils.validators import validate_url
        is_valid, error = validate_url(args.url)
        if not is_valid:
            print(f"Error: {error}", file=sys.stderr)
            return False
    
    # Validate export arguments
    if args.export and not args.output:
        print("Error: --output required when using --export", file=sys.stderr)
        return False
    
    return True


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    logger = logging.getLogger(__name__)
    
    logger.debug(f"Arguments: {args}")
    
    # Validate arguments
    if not validate_args(args):
        return 1
    
    # Create application
    app = Application()
    
    # Determine mode
    if args.project_path:
        # CLI mode
        return app.run_cli(
            project_path=args.project_path,
            url=args.url,
            export_format=args.export,
            export_path=args.output,
            generate_prompt=args.prompt
        )
    else:
        # GUI mode
        return app.run_gui()


if __name__ == '__main__':
    sys.exit(main())
