"""Application configuration constants for SecureMySite."""


class Config:
    """Configuration constants for the application."""
    
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
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.html': 'html',
        '.htm': 'html',
        '.json': 'json',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.toml': 'toml',
        '.ini': 'ini',
        '.cfg': 'config',
        '.env': 'env',
        '.txt': 'text',
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
        '.env',
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
        'site',
        
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
        'config_scanner',
        'dependency_scanner',
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
    EXPORT_FORMATS = ['json', 'html', 'markdown']
    DEFAULT_EXPORT_FORMAT = 'json'
    
    # Update settings
    VULN_DB_UPDATE_INTERVAL_DAYS = 7
    VULN_DB_URL = None  # Offline mode - no external updates
    
    @classmethod
    def is_supported_extension(cls, ext: str) -> bool:
        """Check if file extension is supported."""
        return ext.lower() in cls.SUPPORTED_EXTENSIONS
    
    @classmethod
    def should_exclude(cls, path: str) -> bool:
        """Check if path should be excluded from scanning."""
        import fnmatch
        
        for pattern in cls.EXCLUDE_PATTERNS:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path, f'*/{pattern}'):
                return True
            if pattern in path:
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
