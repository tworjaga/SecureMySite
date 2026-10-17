"""Application configuration constants for SecureMySite."""


APP_VERSION = '2.0.0'


class Config:
    """Configuration constants for the application."""
    
    APP_VERSION = APP_VERSION
    
    # File size limits
    MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB per file
    MAX_PROJECT_SIZE_BYTES = 500 * 1024 * 1024  # 500MB total
    MAX_FILES_TO_SCAN = 10000
    
    # Performance settings
    SCAN_TIMEOUT_SECONDS = 300  # 5 minutes max scan time
    WORKER_THREADS = 4
    
    # Supported file extensions
    SUPPORTED_EXTENSIONS = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',
        '.vue': 'javascript',
        '.svelte': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.html': 'html',
        '.htm': 'html',
        '.j2': 'html',
        '.jinja': 'html',
        '.jinja2': 'html',
        '.njk': 'html',
        '.hbs': 'html',
        '.handlebars': 'html',
        '.ejs': 'html',
        '.mustache': 'html',
        '.json': 'json',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.toml': 'toml',
        '.ini': 'ini',
        '.cfg': 'config',
        '.conf': 'config',
        '.env': 'env',
        '.txt': 'text',
        '.lock': 'text',
        '.pem': 'text',
        '.key': 'text',
    }
    
    # Extension-less (or oddly-suffixed) file names that are always scanned
    SPECIAL_FILENAMES = {
        'dockerfile': 'dockerfile',
        'containerfile': 'dockerfile',
        'pipfile': 'toml',
        '.htpasswd': 'text',
        '.netrc': 'text',
        'id_rsa': 'text',
        'id_dsa': 'text',
        'id_ecdsa': 'text',
        'id_ed25519': 'text',
    }
    
    # Files and directories to exclude
    EXCLUDE_PATTERNS = [
        # Version control
        '.git',
        '.svn',
        '.hg',
        '.bzr',
        
        # Dependencies
        'node_modules',
        'vendor',
        '__pycache__',
        '.venv',
        'venv',
        'env',
        '.tox',
        '.nox',
        
        # Build outputs
        'build',
        'dist',
        'target',
        'out',
        'output',
        '.next',
        '.nuxt',
        
        # IDE and editor files
        '.idea',
        '.vscode',
        '.vs',
        '*.swp',
        '*.swo',
        '*~',
        
        # Test and coverage
        'coverage',
        '.coverage',
        'htmlcov',
        '.pytest_cache',
        '.mypy_cache',
        
        # Logs and temp
        'logs',
        '*.log',
        'tmp',
        'temp',
        '.tmp',
        
        # Binary and media
        '*.exe',
        '*.dll',
        '*.so',
        '*.dylib',
        '*.bin',
        '*.jpg',
        '*.jpeg',
        '*.png',
        '*.gif',
        '*.mp3',
        '*.mp4',
        '*.avi',
        '*.mov',
        '*.zip',
        '*.tar',
        '*.gz',
        '*.rar',
        '*.7z',
        
        # Documentation
        'docs/_build',
        
        # Database files
        '*.db',
        '*.sqlite',
        '*.sqlite3',
    ]
    
    # Sensitive file patterns (should not be in repo)
    SENSITIVE_FILE_PATTERNS = [
        '.env',
        '.env.local',
        '.env.production',
        '.env.development',
        'id_rsa',
        'id_dsa',
        'id_ecdsa',
        'id_ed25519',
        '.htpasswd',
        '.netrc',
        'credentials.json',
        'secrets.json',
        '*.pem',
        '*.key',
        '*.p12',
        '*.pfx',
    ]
    
    # Scanner configuration
    DEFAULT_SCANNERS = [
        'python_sast',
        'javascript_scanner',
        'html_scanner',
        'config_scanner',
        'dependency_scanner',
        'secrets_scanner',
        'iac_scanner',
    ]
    
    # Web scanner is optional (requires localhost URL)
    OPTIONAL_SCANNERS = [
        'web_scanner',
    ]
    
    # Scoring weights
    SEVERITY_WEIGHTS = {
        'CRITICAL': 15,
        'HIGH': 10,
        'MEDIUM': 5,
        'LOW': 2,
    }
    
    # Risk level thresholds
    RISK_LEVELS = [
        (80, 100, 'Safe', 'A+'),
        (75, 79, 'Safe', 'A'),
        (70, 74, 'Moderate', 'A-'),
        (65, 69, 'Moderate', 'B+'),
        (60, 64, 'Moderate', 'B'),
        (55, 59, 'Moderate', 'B-'),
        (50, 54, 'High Risk', 'C+'),
        (45, 49, 'High Risk', 'C'),
        (40, 44, 'High Risk', 'C-'),
        (35, 39, 'Critical Risk', 'D+'),
        (30, 34, 'Critical Risk', 'D'),
        (25, 29, 'Critical Risk', 'D-'),
        (0, 24, 'Critical Risk', 'F'),
    ]
    
    # GUI settings
    GUI_WINDOW_TITLE = 'Secure My Site'
    GUI_MIN_WIDTH = 900
    GUI_MIN_HEIGHT = 600
    GUI_DEFAULT_WIDTH = 1200
    GUI_DEFAULT_HEIGHT = 800
    
    # Theme colors (dark theme)
    THEME = {
        'background': '#1a1a1a',
        'surface': '#2d2d2d',
        'primary': '#00d084',
        'primary_hover': '#00e695',
        'text_primary': '#ffffff',
        'text_secondary': '#a0a0a0',
        'border': '#3d3d3d',
        'critical': '#ff4444',
        'high': '#ff8800',
        'medium': '#ffcc00',
        'low': '#00ccff',
    }
    
    # Export settings
    EXPORT_FORMATS = ['json', 'html', 'markdown', 'sarif', 'csv']
    DEFAULT_EXPORT_FORMAT = 'json'
    
    # Update settings
    VULN_DB_UPDATE_INTERVAL_DAYS = 7
    VULN_DB_URL = None  # Offline mode - no external updates
    
    @classmethod
    def is_supported_extension(cls, ext: str) -> bool:
        """Check if file extension is supported."""
        return ext.lower() in cls.SUPPORTED_EXTENSIONS
    
    @classmethod
    def get_language(cls, filename: str) -> 'str | None':
        """Resolve the scan language for a file name (handles .env.*, Dockerfile, etc.)."""
        from pathlib import PurePath
        
        name = PurePath(filename).name.lower()
        if name in cls.SPECIAL_FILENAMES:
            return cls.SPECIAL_FILENAMES[name]
        if name == '.env' or name.startswith('.env.'):
            return 'env'
        if name.startswith('dockerfile.') or name.endswith('.dockerfile'):
            return 'dockerfile'
        return cls.SUPPORTED_EXTENSIONS.get(PurePath(name).suffix)
    
    @classmethod
    def should_exclude(cls, path: str) -> bool:
        """
        Check if a project-relative path should be excluded from scanning.

        Patterns are matched against whole path components (and the full
        relative path for multi-segment patterns like 'docs/_build'), never as
        substrings - so 'layout.py' is not excluded by the 'out' pattern.
        """
        import fnmatch
        from pathlib import PurePath

        normalized = str(path).replace('\\', '/')
        parts = PurePath(normalized).parts
        name = parts[-1] if parts else normalized

        for pattern in cls.EXCLUDE_PATTERNS:
            if '/' in pattern:
                if normalized == pattern or normalized.startswith(pattern + '/'):
                    return True
                continue
            if pattern.startswith('*'):
                # File glob: only applies to the file name
                if fnmatch.fnmatch(name, pattern):
                    return True
                continue
            # Directory name: any parent component must match exactly
            if pattern in parts[:-1]:
                return True

        return False

    @classmethod
    def is_excluded_dir_name(cls, dir_name: str) -> bool:
        """Check if a directory name matches an exclusion pattern."""
        import fnmatch

        for pattern in cls.EXCLUDE_PATTERNS:
            if '/' in pattern or pattern.startswith('*'):
                continue
            if fnmatch.fnmatch(dir_name, pattern):
                return True
        return False
    
    @classmethod
    def is_sensitive_file(cls, filename: str) -> bool:
        """Check if filename matches sensitive file patterns."""
        import fnmatch
        
        for pattern in cls.SENSITIVE_FILE_PATTERNS:
            if fnmatch.fnmatch(filename, pattern):
                return True
        
        return False
