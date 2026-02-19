<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use Illuminate\Contracts\Config\Repository as Config;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

/**
 * Detects hardcoded storage paths instead of Laravel helpers.
 */
class HardcodedStoragePathsAnalyzer extends AbstractFileAnalyzer
{
    /** @var array<int, string> */
    private array $allowedPaths;

    /**
     * Patterns that should ALWAYS be flagged regardless of context.
     * These are clearly filesystem paths (absolute system paths, relative paths).
     *
     * @var array<string, string>
     */
    private array $alwaysFlagPatterns;

    /**
     * Patterns that should ONLY be flagged when used in filesystem context.
     * These could be web routes or URL paths in non-filesystem usage.
     *
     * @var array<string, string>
     */
    private array $contextRequiredPatterns;

    public function __construct(
        private ParserInterface $parser,
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'hardcoded-storage-paths',
            name: 'Hardcoded Storage Paths Analyzer',
            description: 'Finds hardcoded storage/public paths instead of Laravel path helpers',
            category: Category::BestPractices,
            severity: Severity::Medium,
            tags: ['laravel', 'portability', 'paths', 'configuration'],
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Load configuration
        $analyzerConfig = $this->config->get('shieldci.analyzers.best-practices.hardcoded-storage-paths', []);
        $analyzerConfig = is_array($analyzerConfig) ? $analyzerConfig : [];

        $this->allowedPaths = $analyzerConfig['allowed_paths'] ?? [];
        $additionalPatterns = $analyzerConfig['additional_patterns'] ?? [];

        // Patterns that ALWAYS indicate hardcoded paths (absolute system paths, relative paths)
        // These are clearly filesystem paths regardless of context
        $this->alwaysFlagPatterns = [
            // Absolute Unix paths (most likely to be hardcoded)
            // Match /var/www/storage/, /var/www/html/storage/, etc.
            '/\/var\/www\/.*storage/i' => 'storage_path(...)',
            '/\/var\/www\/.*public/i' => 'public_path(...)',
            '/\/var\/www\/.*app\//i' => 'app_path(...)',
            '/\/var\/www\/.*resources/i' => 'resource_path(...)',
            '/\/var\/www\/.*database/i' => 'database_path(...)',
            '/\/var\/www\/.*config/i' => 'config_path(...)',

            // Windows absolute paths
            '/[A-Z]:\\\\storage\\\\app\\\\/i' => 'storage_path(\'app/...\')',
            '/[A-Z]:\\\\storage\\\\logs\\\\/i' => 'storage_path(\'logs/...\')',
            '/[A-Z]:\\\\storage\\\\framework\\\\/i' => 'storage_path(\'framework/...\')',
            '/[A-Z]:\\\\storage\\\\/i' => 'storage_path(...)',
            '/[A-Z]:\\\\public\\\\uploads\\\\/i' => 'public_path(\'uploads/...\')',
            '/[A-Z]:\\\\public\\\\images\\\\/i' => 'public_path(\'images/...\')',
            '/[A-Z]:\\\\public\\\\/i' => 'public_path(...)',
            '/[A-Z]:\\\\app\\\\/i' => 'app_path(...)',
            '/[A-Z]:\\\\resources\\\\/i' => 'resource_path(...)',
            '/[A-Z]:\\\\database\\\\/i' => 'database_path(...)',
            '/[A-Z]:\\\\config\\\\/i' => 'config_path(...)',

            // Relative paths with ../ or ./
            '/\.\.\/storage\//i' => 'storage_path(...)',
            '/\.\.\/public\//i' => 'public_path(...)',
            '/\.\.\/app\//i' => 'app_path(...)',
            '/\.\.\/resources\//i' => 'resource_path(...)',
            '/\.\.\/database\//i' => 'database_path(...)',
            '/\.\.\/config\//i' => 'config_path(...)',
            '/\.\/storage\//i' => 'storage_path(...)',
            '/\.\/public\//i' => 'public_path(...)',
            '/\.\/app\//i' => 'app_path(...)',
            '/\.\/resources\//i' => 'resource_path(...)',
            '/\.\/database\//i' => 'database_path(...)',
            '/\.\/config\//i' => 'config_path(...)',
        ];

        // Patterns that could be web routes or URL paths, so they ONLY
        // get flagged when used as arguments to filesystem functions
        $this->contextRequiredPatterns = [
            // Leading slash paths (could be web routes or filesystem paths)
            '/^\/storage\/app\//i' => 'storage_path(\'app/...\')',
            '/^\/storage\/logs\//i' => 'storage_path(\'logs/...\')',
            '/^\/storage\/framework\//i' => 'storage_path(\'framework/...\')',
            '/^\/storage\//i' => 'storage_path(...)',
            '/^\/public\/uploads\//i' => 'public_path(\'uploads/...\')',
            '/^\/public\/images\//i' => 'public_path(\'images/...\')',
            '/^\/public\//i' => 'public_path(...)',
            '/^\/app\//i' => 'app_path(...)',
            '/^\/resources\//i' => 'resource_path(...)',
            '/^\/database\//i' => 'database_path(...)',
            '/^\/config\//i' => 'config_path(...)',
        ];

        // Merge with additional patterns from config (added to always-flag patterns)
        $this->alwaysFlagPatterns = array_merge($this->alwaysFlagPatterns, $additionalPatterns);

        $issues = [];
        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new HardcodedPathsVisitor(
                    $this->alwaysFlagPatterns,
                    $this->contextRequiredPatterns,
                    $this->allowedPaths
                );
                $traverser = new NodeTraverser;
                // ParentConnectingVisitor MUST be added first to enable parent node tracking
                $traverser->addVisitor(new ParentConnectingVisitor);
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssueWithSnippet(
                        message: $issue['message'],
                        filePath: $file,
                        lineNumber: $issue['line'],
                        severity: $issue['severity'],
                        recommendation: $issue['recommendation'],
                        code: $issue['code'] ?? null,
                    );
                }
            } catch (\Throwable $e) {
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('All paths use Laravel helpers');
        }

        return $this->resultBySeverity(
            sprintf('Found %d hardcoded path(s)', count($issues)),
            $issues
        );
    }
}

class HardcodedPathsVisitor extends NodeVisitorAbstract
{
    /** @var array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}> */
    private array $issues = [];

    /**
     * Context strength levels for filesystem detection.
     */
    private const CONTEXT_NONE = 0;    // Not a filesystem context

    private const CONTEXT_WEAK = 1;    // Heuristic-based (variable name hints)

    private const CONTEXT_STRONG = 2;  // Definite (known functions/facades)

    /**
     * Context types for recommendation selection.
     */
    private const CONTEXT_TYPE_FILESYSTEM = 'filesystem';

    private const CONTEXT_TYPE_ASSET = 'asset';

    /**
     * PHP functions that operate on the filesystem.
     *
     * @var array<int, string>
     */
    private const FILESYSTEM_FUNCTIONS = [
        // File reading/writing
        'file_get_contents',
        'file_put_contents',
        'fopen',
        'fread',
        'fwrite',
        'fclose',
        'file',
        'readfile',
        'fgets',
        'fgetc',
        'fgetcsv',
        'fputcsv',

        // File/directory checks
        'file_exists',
        'is_file',
        'is_dir',
        'is_readable',
        'is_writable',
        'is_writeable',
        'is_executable',
        'is_link',

        // Directory operations
        'mkdir',
        'rmdir',
        'opendir',
        'readdir',
        'closedir',
        'scandir',
        'glob',

        // File operations
        'unlink',
        'copy',
        'rename',
        'move_uploaded_file',
        'chmod',
        'chown',
        'chgrp',
        'touch',
        'link',
        'symlink',
        'readlink',

        // File info
        'filesize',
        'filetype',
        'filemtime',
        'fileatime',
        'filectime',
        'stat',
        'lstat',
        'pathinfo',
        'realpath',
        'dirname',
        'basename',
    ];

    /**
     * Laravel File/Storage facade static methods that operate on filesystem.
     *
     * @var array<int, string>
     */
    private const FILESYSTEM_STATIC_METHODS = [
        // Storage facade
        'get',
        'put',
        'exists',
        'missing',
        'path',
        'delete',
        'copy',
        'move',
        'size',
        'lastModified',
        'files',
        'allFiles',
        'directories',
        'allDirectories',
        'makeDirectory',
        'deleteDirectory',
        'append',
        'prepend',
        'read',
        'write',
        'readStream',
        'writeStream',
    ];

    /**
     * Instance method names that suggest filesystem operations.
     *
     * @var array<int, string>
     */
    private const FILESYSTEM_INSTANCE_METHODS = [
        'get',
        'put',
        'exists',
        'delete',
        'copy',
        'move',
        'read',
        'write',
        'append',
        'prepend',
        'size',
        'lastModified',
        'path',
    ];

    /**
     * Storage facade methods that produce URLs (not filesystem operations).
     *
     * @var array<int, string>
     */
    private const URL_PRODUCING_STORAGE_METHODS = [
        'url',
        'temporaryurl',
    ];

    /**
     * Method names that produce URLs when called on URL-related objects.
     *
     * @var array<int, string>
     */
    private const URL_PRODUCING_METHODS = [
        'to',
        'route',
        'action',
        'asset',
        'secure',
        'signedroute',
        'temporarysignedroute',
    ];

    /**
     * Laravel File/Storage facade class names.
     *
     * @var array<int, string>
     */
    private const FILESYSTEM_FACADE_CLASSES = [
        'Storage',
        'File',
        'Illuminate\\Support\\Facades\\Storage',
        'Illuminate\\Support\\Facades\\File',
    ];

    /**
     * UploadedFile class names.
     *
     * @var array<int, string>
     */
    private const UPLOAD_FILE_CLASSES = [
        'UploadedFile',
        'Illuminate\\Http\\UploadedFile',
        'Symfony\\Component\\HttpFoundation\\File\\UploadedFile',
    ];

    /**
     * Service container names that resolve to filesystem.
     *
     * @var array<int, string>
     */
    private const FILESYSTEM_SERVICE_NAMES = [
        'files',
        'filesystem',
        'Illuminate\\Filesystem\\Filesystem',
        'Illuminate\\Contracts\\Filesystem\\Filesystem',
    ];

    /**
     * Response methods that operate on files.
     *
     * @var array<int, string>
     */
    private const RESPONSE_FILE_METHODS = [
        'download',
        'file',
        'streamDownload',
    ];

    /**
     * Laravel helpers that generate URLs/assets (not filesystem paths).
     *
     * @var array<int, string>
     */
    private const ASSET_HELPER_FUNCTIONS = [
        'asset',
        'secure_asset',
        'mix',
        'url',
        'secure_url',
        'route',
        'action',
        'to_route',
        'redirect',
    ];

    /**
     * Patterns that require STRONG context (could be web routes).
     * Only flag when used in definite filesystem context.
     *
     * @var array<int, string>
     */
    private const STRONG_CONTEXT_PATTERNS = [
        '/^\/public\//i',
        '/^\/app\//i',
    ];

    /**
     * @param  array<string, string>  $alwaysFlagPatterns  Patterns to always flag regardless of context
     * @param  array<string, string>  $contextRequiredPatterns  Patterns that only flag in filesystem context
     * @param  array<int, string>  $allowedPaths
     */
    public function __construct(
        private array $alwaysFlagPatterns,
        private array $contextRequiredPatterns,
        private array $allowedPaths
    ) {}

    public function enterNode(Node $node): ?Node
    {
        // Handle regular strings
        if ($node instanceof Node\Scalar\String_) {
            $this->checkPath($node->value, $node->getLine(), $node);
        }

        // Handle heredoc/nowdoc strings
        if ($node instanceof Node\Scalar\Encapsed) {
            $fullString = '';
            foreach ($node->parts as $part) {
                if ($part instanceof Node\Scalar\EncapsedStringPart) {
                    $fullString .= $part->value;
                }
            }
            if ($fullString !== '') {
                $this->checkPath($fullString, $node->getLine(), $node);
            }
        }

        return null;
    }

    /**
     * Check if a string value contains a hardcoded path.
     */
    private function checkPath(string $value, int $line, Node $node): void
    {
        // Skip URLs (false positives)
        if (preg_match('/^https?:\/\//i', $value)) {
            return;
        }

        // Skip if in allowed paths list
        foreach ($this->allowedPaths as $allowedPath) {
            if (str_contains($value, $allowedPath)) {
                return;
            }
        }

        // Check "always flag" patterns first (absolute system paths, relative paths)
        foreach ($this->alwaysFlagPatterns as $pattern => $helper) {
            if (preg_match($pattern, $value)) {
                $this->issues[] = [
                    'message' => sprintf('Hardcoded storage path found: "%s"', substr($value, 0, 50)),
                    'line' => $line,
                    'severity' => Severity::Medium,
                    'recommendation' => sprintf('Use Laravel path helper: %s. This ensures portability across environments and enables different storage drivers', $helper),
                    'code' => null,
                ];

                return; // Only report once per string
            }
        }

        // Check "context required" patterns (could be web routes)
        // Only flag if used in filesystem context with appropriate strength
        foreach ($this->contextRequiredPatterns as $pattern => $helper) {
            if (preg_match($pattern, $value)) {
                $contextStrength = $this->getFilesystemContextStrength($node);

                // For patterns that could easily be web routes (like /public/, /app/),
                // require STRONG context. For others, WEAK context is sufficient.
                $requiredStrength = $this->patternRequiresStrongContext($pattern)
                    ? self::CONTEXT_STRONG
                    : self::CONTEXT_WEAK;

                if ($contextStrength >= $requiredStrength) {
                    $recommendation = $this->getContextAwareRecommendation($pattern, $helper, $node);
                    $this->issues[] = [
                        'message' => sprintf('Hardcoded storage path found: "%s"', substr($value, 0, 50)),
                        'line' => $line,
                        'severity' => Severity::Medium,
                        'recommendation' => $recommendation,
                        'code' => null,
                    ];
                }

                return; // Only report once per string (or skip if not filesystem context)
            }
        }
    }

    /**
     * Check if a pattern requires STRONG filesystem context to flag.
     */
    private function patternRequiresStrongContext(string $pattern): bool
    {
        foreach (self::STRONG_CONTEXT_PATTERNS as $strongPattern) {
            if ($strongPattern === $pattern) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get context-aware recommendation based on usage context.
     */
    private function getContextAwareRecommendation(string $pattern, string $defaultHelper, Node $node): string
    {
        $contextType = $this->getContextType($node);

        // For /public/ paths, recommend based on context
        if (preg_match('/public/i', $pattern)) {
            return match ($contextType) {
                self::CONTEXT_TYPE_ASSET => "Use asset('...') for URLs in templates instead of hardcoded paths",
                self::CONTEXT_TYPE_FILESYSTEM => sprintf('Use Laravel path helper: %s. This ensures portability across environments', $defaultHelper),
                default => sprintf('Use Laravel path helper: %s. This ensures portability across environments and enables different storage drivers', $defaultHelper),
            };
        }

        return sprintf('Use Laravel path helper: %s. This ensures portability across environments and enables different storage drivers', $defaultHelper);
    }

    /**
     * Determine the context type (filesystem or asset) for a node.
     */
    private function getContextType(Node $node): ?string
    {
        $parent = $node->getAttribute('parent');

        while ($parent !== null) {
            // Check for asset/URL functions
            if ($parent instanceof Node\Expr\FuncCall) {
                if ($parent->name instanceof Node\Name) {
                    $funcName = strtolower($parent->name->toString());
                    if (in_array($funcName, self::ASSET_HELPER_FUNCTIONS, true)) {
                        return self::CONTEXT_TYPE_ASSET;
                    }
                    if (in_array($funcName, self::FILESYSTEM_FUNCTIONS, true)) {
                        return self::CONTEXT_TYPE_FILESYSTEM;
                    }
                }
                break;
            }

            // Check for url()->to(), url()->route(), etc.
            if ($parent instanceof Node\Expr\MethodCall) {
                if ($parent->name instanceof Node\Identifier) {
                    $methodName = strtolower($parent->name->toString());

                    // Check if calling URL-producing method on url() helper result
                    if (in_array($methodName, self::URL_PRODUCING_METHODS, true)) {
                        if ($parent->var instanceof Node\Expr\FuncCall) {
                            if ($parent->var->name instanceof Node\Name) {
                                $funcName = strtolower($parent->var->name->toString());
                                if ($funcName === 'url') {
                                    return self::CONTEXT_TYPE_ASSET;
                                }
                            }
                        }
                    }
                }

                // Continue traversing for method chains
                $parent = $parent->getAttribute('parent');

                continue;
            }

            // Check for static facade calls
            if ($parent instanceof Node\Expr\StaticCall) {
                if ($parent->class instanceof Node\Name && $parent->name instanceof Node\Identifier) {
                    $className = $parent->class->toString();
                    $methodName = strtolower($parent->name->toString());

                    // Storage/File facades - check method before assuming filesystem
                    if (in_array($className, self::FILESYSTEM_FACADE_CLASSES, true)) {
                        // Storage::url() and Storage::temporaryUrl() produce URLs, not filesystem ops
                        if (in_array($methodName, self::URL_PRODUCING_STORAGE_METHODS, true)) {
                            return self::CONTEXT_TYPE_ASSET;
                        }

                        return self::CONTEXT_TYPE_FILESYSTEM;
                    }

                    // Vite::asset() -> asset context
                    if (in_array($className, ['Vite', 'Illuminate\\Support\\Facades\\Vite'], true)) {
                        if ($methodName === 'asset') {
                            return self::CONTEXT_TYPE_ASSET;
                        }
                    }

                    // URL facade -> asset context
                    if (in_array($className, ['URL', 'Illuminate\\Support\\Facades\\URL'], true)) {
                        return self::CONTEXT_TYPE_ASSET;
                    }
                }
                break;
            }

            // Continue through concat, array, arg nodes
            if ($parent instanceof Node\Expr\BinaryOp\Concat
                || $parent instanceof Node\Expr\ArrayItem
                || $parent instanceof Node\Arg) {
                $parent = $parent->getAttribute('parent');

                continue;
            }

            break;
        }

        return null;
    }

    /**
     * Get the filesystem context strength for a node.
     *
     * Returns CONTEXT_STRONG for definite filesystem operations (known functions/facades),
     * CONTEXT_WEAK for heuristic-based detection (variable name hints),
     * CONTEXT_NONE if not in filesystem context.
     */
    private function getFilesystemContextStrength(Node $node): int
    {
        $parent = $node->getAttribute('parent');

        while ($parent !== null) {
            // STRONG: Direct PHP filesystem functions
            if ($parent instanceof Node\Expr\FuncCall) {
                if ($parent->name instanceof Node\Name) {
                    $funcName = strtolower($parent->name->toString());
                    if (in_array($funcName, self::FILESYSTEM_FUNCTIONS, true)) {
                        return $this->isArgumentOf($node, $parent)
                            ? self::CONTEXT_STRONG
                            : self::CONTEXT_NONE;
                    }
                }
                break;
            }

            // STRONG: Storage/File facade static calls
            if ($parent instanceof Node\Expr\StaticCall) {
                if ($parent->class instanceof Node\Name && $parent->name instanceof Node\Identifier) {
                    $className = $parent->class->toString();
                    $methodName = strtolower($parent->name->toString());

                    if (in_array($className, self::FILESYSTEM_FACADE_CLASSES, true)) {
                        if (in_array($methodName, self::FILESYSTEM_STATIC_METHODS, true)) {
                            return $this->isArgumentOf($node, $parent)
                                ? self::CONTEXT_STRONG
                                : self::CONTEXT_NONE;
                        }
                    }

                    // STRONG: UploadedFile static methods
                    if (in_array($className, self::UPLOAD_FILE_CLASSES, true)) {
                        return $this->isArgumentOf($node, $parent)
                            ? self::CONTEXT_STRONG
                            : self::CONTEXT_NONE;
                    }
                }
                break;
            }

            // Method calls - check for strong or weak context
            if ($parent instanceof Node\Expr\MethodCall) {
                if ($parent->name instanceof Node\Identifier) {
                    $methodName = strtolower($parent->name->toString());

                    // STRONG: Chained on Storage::disk() or File::*
                    if ($parent->var instanceof Node\Expr\StaticCall) {
                        $staticCall = $parent->var;
                        if ($staticCall->class instanceof Node\Name) {
                            $className = $staticCall->class->toString();
                            if (in_array($className, self::FILESYSTEM_FACADE_CLASSES, true)) {
                                if (in_array($methodName, self::FILESYSTEM_INSTANCE_METHODS, true)) {
                                    return $this->isArgumentOf($node, $parent)
                                        ? self::CONTEXT_STRONG
                                        : self::CONTEXT_NONE;
                                }
                            }
                        }
                    }

                    // STRONG: app('files')->method() or resolve('filesystem')->method()
                    if ($parent->var instanceof Node\Expr\FuncCall) {
                        if ($this->isFilesystemServiceResolution($parent->var)) {
                            if (in_array($methodName, self::FILESYSTEM_INSTANCE_METHODS, true)) {
                                return $this->isArgumentOf($node, $parent)
                                    ? self::CONTEXT_STRONG
                                    : self::CONTEXT_NONE;
                            }
                        }
                    }

                    // STRONG: response()->download() / $response->download()
                    if ($this->isResponseFileMethod($parent)) {
                        return $this->isArgumentOf($node, $parent)
                            ? self::CONTEXT_STRONG
                            : self::CONTEXT_NONE;
                    }

                    // WEAK: Variable name heuristics ($filesystem->get, $file->put)
                    if (in_array($methodName, self::FILESYSTEM_INSTANCE_METHODS, true)) {
                        if ($this->isFilesystemVariable($parent->var)) {
                            return $this->isArgumentOf($node, $parent)
                                ? self::CONTEXT_WEAK
                                : self::CONTEXT_NONE;
                        }
                    }
                }
                break;
            }

            // Continue through concat, array, arg nodes
            if ($parent instanceof Node\Expr\BinaryOp\Concat
                || $parent instanceof Node\Expr\ArrayItem
                || $parent instanceof Node\Arg) {
                $parent = $parent->getAttribute('parent');

                continue;
            }

            break;
        }

        return self::CONTEXT_NONE;
    }

    /**
     * Check if a function call is resolving a filesystem service from the container.
     *
     * Matches: app('files'), app('filesystem'), resolve('files'), etc.
     */
    private function isFilesystemServiceResolution(Node\Expr\FuncCall $funcCall): bool
    {
        if (! $funcCall->name instanceof Node\Name) {
            return false;
        }

        $funcName = strtolower($funcCall->name->toString());
        if ($funcName !== 'app' && $funcName !== 'resolve') {
            return false;
        }

        if (empty($funcCall->args) || ! $funcCall->args[0] instanceof Node\Arg) {
            return false;
        }

        $firstArg = $funcCall->args[0]->value;
        if ($firstArg instanceof Node\Scalar\String_) {
            return in_array($firstArg->value, self::FILESYSTEM_SERVICE_NAMES, true);
        }

        if ($firstArg instanceof Node\Expr\ClassConstFetch) {
            if ($firstArg->class instanceof Node\Name) {
                $className = $firstArg->class->toString();

                return str_contains($className, 'Filesystem');
            }
        }

        return false;
    }

    /**
     * Check if a method call is a response file method (download, file, streamDownload).
     */
    private function isResponseFileMethod(Node\Expr\MethodCall $methodCall): bool
    {
        if (! $methodCall->name instanceof Node\Identifier) {
            return false;
        }

        $methodName = strtolower($methodCall->name->toString());
        if (! in_array($methodName, self::RESPONSE_FILE_METHODS, true)) {
            return false;
        }

        // Check response() helper: response()->download(...)
        if ($methodCall->var instanceof Node\Expr\FuncCall) {
            if ($methodCall->var->name instanceof Node\Name) {
                return strtolower($methodCall->var->name->toString()) === 'response';
            }
        }

        // Check $response variable: $response->download(...)
        if ($methodCall->var instanceof Node\Expr\Variable) {
            return is_string($methodCall->var->name) &&
                   strtolower($methodCall->var->name) === 'response';
        }

        return false;
    }

    /**
     * Variable names that suggest filesystem operations.
     *
     * @var array<int, string>
     */
    private const FILESYSTEM_VARIABLE_HINTS = [
        'file',
        'filesystem',
        'storage',
        'disk',
        'fs',
        'directory',
        'dir',
    ];

    /**
     * Check if a variable likely represents a filesystem object.
     */
    private function isFilesystemVariable(Node\Expr $var): bool
    {
        // Check direct variable names
        if ($var instanceof Node\Expr\Variable && is_string($var->name)) {
            $varName = strtolower($var->name);
            foreach (self::FILESYSTEM_VARIABLE_HINTS as $hint) {
                if (str_contains($varName, $hint)) {
                    return true;
                }
            }
        }

        // Check property fetch ($this->filesystem, $this->file, etc.)
        if ($var instanceof Node\Expr\PropertyFetch && $var->name instanceof Node\Identifier) {
            $propName = strtolower($var->name->toString());
            foreach (self::FILESYSTEM_VARIABLE_HINTS as $hint) {
                if (str_contains($propName, $hint)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if the given node is an argument of the given call node.
     */
    private function isArgumentOf(Node $node, Node\Expr\FuncCall|Node\Expr\StaticCall|Node\Expr\MethodCall $callNode): bool
    {
        foreach ($callNode->args as $arg) {
            if (! $arg instanceof Node\Arg) {
                continue;
            }

            // Direct match
            if ($arg->value === $node) {
                return true;
            }

            // Check if node is contained within the argument (nested in concat, array, etc.)
            if ($this->nodeContains($arg->value, $node)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a parent node contains a child node.
     */
    private function nodeContains(Node $parent, Node $target): bool
    {
        if ($parent === $target) {
            return true;
        }

        // Check concat expressions
        if ($parent instanceof Node\Expr\BinaryOp\Concat) {
            return $this->nodeContains($parent->left, $target)
                || $this->nodeContains($parent->right, $target);
        }

        // Check array items
        if ($parent instanceof Node\Expr\Array_) {
            foreach ($parent->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem && $this->nodeContains($item->value, $target)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return array<int, array{message: string, line: int, severity: Severity, recommendation: string, code: string|null}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
