<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

use PhpParser\Comment\Doc;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\CloningVisitor;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Concerns\ClassifiesFiles;

/**
 * Flags public methods without documentation.
 *
 * Checks for:
 * - Public methods missing PHPDoc comments
 * - Requires @param, @return, @throws tags
 * - Excludes simple getters/setters
 */
class MissingDocBlockAnalyzer extends AbstractFileAnalyzer
{
    use ClassifiesFiles;

    /**
     * @var array<string>
     */
    private array $excludedPatterns = ['get*', 'set*', 'is*', 'has*'];

    /**
     * Mailable framework-contract methods (Illuminate\Mail\Mailable). Lowercased.
     *
     * @var array<string>
     */
    private const MAILABLE_METHODS = ['envelope', 'content', 'attachments', 'headers', 'build'];

    /**
     * FormRequest framework-contract methods (Illuminate\Foundation\Http\FormRequest). Lowercased.
     *
     * @var array<string>
     */
    private const FORM_REQUEST_METHODS = ['authorize', 'rules', 'messages', 'attributes', 'prepareforvalidation', 'withvalidator'];

    /**
     * Queued-job / listener framework-contract methods. Lowercased.
     *
     * @var array<string>
     */
    private const QUEUE_METHODS = ['handle', 'failed'];

    /**
     * HTTP middleware framework-contract methods. Lowercased.
     *
     * @var array<string>
     */
    private const MIDDLEWARE_METHODS = ['handle', 'terminate'];

    /**
     * Eloquent global-scope framework-contract methods (Illuminate\Database\Eloquent\Scope). Lowercased.
     *
     * @var array<string>
     */
    private const SCOPE_METHODS = ['apply'];

    /**
     * Validation rule object contract methods (modern ValidationRule + legacy Rule). Lowercased.
     *
     * @var array<string>
     */
    private const VALIDATION_RULE_METHODS = ['validate'];

    /**
     * @var array<string>
     */
    private const LEGACY_RULE_METHODS = ['passes', 'message'];

    /**
     * Responsable contract method (Illuminate\Contracts\Support\Responsable). Lowercased.
     *
     * @var array<string>
     */
    private const RESPONSABLE_METHODS = ['toresponse'];

    /**
     * Console command framework-contract method (Illuminate\Console\Command). Lowercased.
     *
     * @var array<string>
     */
    private const CONSOLE_METHODS = ['handle'];

    /**
     * Notification channel framework-contract methods (Illuminate\Notifications\Notification). Lowercased.
     *
     * @var array<string>
     */
    private const NOTIFICATION_METHODS = ['via', 'tomail', 'todatabase', 'toarray', 'tobroadcast', 'tovonage', 'toslack'];

    /**
     * API resource framework-contract methods (Illuminate\Http\Resources\Json\JsonResource). Lowercased.
     *
     * @var array<string>
     */
    private const JSON_RESOURCE_METHODS = ['toarray', 'with', 'withresponse'];

    /**
     * Filament framework override methods whose meaning and signature are fixed by the
     * framework contract. Documenting them adds only noise. Lowercased.
     *
     * @var array<string>
     */
    private const FILAMENT_OVERRIDES = [
        'form', 'table', 'infolist', 'panel',
        'canaccess', 'canview', 'canviewany', 'cancreate', 'canedit', 'candelete',
        'canviewforrecord', 'canforcedelete', 'canforcedeleteany', 'candeleteany',
        'canrestore', 'canrestoreany', 'canreorder', 'canreplicate',
    ];

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'missing-docblock',
            name: 'Missing DocBlock Analyzer',
            description: 'Flags public methods without proper PHPDoc documentation for better code maintainability',
            category: Category::CodeQuality,
            severity: Severity::Low,
            tags: ['documentation', 'maintainability', 'code-quality', 'readability'],
            timeToFix: 15
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $excludePatterns = $this->excludedPatterns;
        $requireTags = true;

        foreach ($this->getPhpFiles() as $file) {
            // Skip Laravel scaffolding/test-support files (migrations, factories,
            // seeders). Their framework hooks (up/down, configure, definition) and
            // trivial state methods make docblock enforcement pure noise.
            //
            // Controllers are skipped wholesale too: their public methods are all route
            // actions (HTTP glue with framework-invoked, typed signatures), so a docblock
            // only restates the action — the same noise whether the name is a REST
            // convention (store) or app-specific (switch).
            if ($this->isDevelopmentFile($file) || $this->isControllerFile($file)) {
                continue;
            }

            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new DocBlockVisitor($excludePatterns, $requireTags, $this->getContractMethodsToSkip($ast, $file));
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssueWithSnippet(
                    message: $issue['message'],
                    filePath: $file,
                    lineNumber: $issue['line'],
                    severity: $this->metadata()->severity,
                    recommendation: $this->getRecommendation(
                        $issue['type'],
                        $issue['method'],
                        $issue['needsParam'] ?? false,
                        $issue['needsReturn'] ?? false,
                        $issue['needsThrows'] ?? false,
                    ),
                    column: null,
                    contextLines: null,
                    metadata: [
                        'method' => $issue['method'],
                        'class' => $issue['class'],
                        'issue_type' => $issue['type'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('All public methods have proper documentation');
        }

        $totalIssues = count($issues);

        // Count unique methods affected (one method can have multiple issues)
        $uniqueMethods = [];
        foreach ($issues as $issue) {
            $class = is_string($issue->metadata['class'] ?? null) ? $issue->metadata['class'] : '';
            $method = is_string($issue->metadata['method'] ?? null) ? $issue->metadata['method'] : '';
            $methodKey = $class.'@'.$method;
            $uniqueMethods[$methodKey] = true;
        }
        $affectedMethodCount = count($uniqueMethods);

        $issueWord = $totalIssues === 1 ? 'issue' : 'issues';
        $methodWord = $affectedMethodCount === 1 ? 'method' : 'methods';

        return $this->resultBySeverity(
            "Found {$totalIssues} documentation {$issueWord} across {$affectedMethodCount} public {$methodWord}",
            $issues
        );
    }

    /**
     * Build the set of framework-contract method names to skip for this file.
     *
     * These are methods whose meaning and signature are fixed by a Laravel framework
     * contract (Mailable, FormRequest, queued Job/Listener, Filament UI, …), so a docblock
     * only restates the obvious — the same "framework hook = noise" principle already
     * applied to Filament classes and dev files. (Controllers are handled separately, as a
     * whole-file skip in runAnalysis.)
     *
     * Detection is gated by class type (base class, interface, namespace, or path) so
     * identically-named methods in plain classes — a repository's store()/update(), a
     * service's handle() — are NOT skipped. Like the previous Filament detection, this
     * is file-level: the union across all classes in the file. Laravel is one class per
     * file under PSR-4, so this matches existing behaviour.
     *
     * Uses one CloningVisitor + NameResolver traversal to resolve parent/interface names
     * to FQN before checking, mirroring the detector pattern used across the analyzers.
     *
     * @param  array<Node>  $ast
     * @return array<string> lowercased contract-method names to skip
     */
    private function getContractMethodsToSkip(array $ast, string $file): array
    {
        $methods = [];

        // Path-based gating (independent of AST): many jobs/listeners are detectable by
        // location even when they extend no base class.
        if (str_contains($file, '/Jobs/') || str_contains($file, '/Listeners/')) {
            $methods = array_merge($methods, self::QUEUE_METHODS);
        }

        if (str_contains($file, '/Http/Middleware/')) {
            $methods = array_merge($methods, self::MIDDLEWARE_METHODS);
        }

        if ($this->isConsoleCommand($file)) {
            $methods = array_merge($methods, self::CONSOLE_METHODS);
        }

        $traverser = new NodeTraverser;
        $traverser->addVisitor(new CloningVisitor);
        $traverser->addVisitor(new NameResolver);
        $resolvedAst = $traverser->traverse($ast);

        foreach ($resolvedAst as $node) {
            if ($node instanceof Stmt\Namespace_) {
                $namespace = $node->name?->toString();

                foreach ($node->stmts as $stmt) {
                    if ($stmt instanceof Stmt\Class_) {
                        $methods = array_merge($methods, $this->contractMethodsForClass($stmt, $namespace));
                    }
                }
            } elseif ($node instanceof Stmt\Class_) {
                $methods = array_merge($methods, $this->contractMethodsForClass($node, null));
            }
        }

        return array_values(array_unique($methods));
    }

    /**
     * Determine which framework-contract method names apply to a single class, based on
     * its base class, implemented interfaces, and namespace.
     *
     * @return array<string> lowercased contract-method names
     */
    private function contractMethodsForClass(Stmt\Class_ $class, ?string $namespace): array
    {
        $methods = [];

        if ($this->extendsMailable($class)) {
            $methods = array_merge($methods, self::MAILABLE_METHODS);
        }

        if ($this->extendsFormRequest($class)) {
            $methods = array_merge($methods, self::FORM_REQUEST_METHODS);
        }

        if ($this->implementsShouldQueue($class) || $this->isJobOrListenerNamespace($namespace)) {
            $methods = array_merge($methods, self::QUEUE_METHODS);
        }

        if ($this->isMiddlewareNamespace($namespace)) {
            $methods = array_merge($methods, self::MIDDLEWARE_METHODS);
        }

        if ($this->implementsScope($class)) {
            $methods = array_merge($methods, self::SCOPE_METHODS);
        }

        if ($this->classImplements($class, 'Illuminate\\Contracts\\Validation\\ValidationRule')) {
            $methods = array_merge($methods, self::VALIDATION_RULE_METHODS);
        }

        // Legacy Rule contract matched by exact FQN only — '\Rule' is too common a short
        // name to suffix-match without risking false exemptions in unrelated classes.
        if ($this->classImplements($class, 'Illuminate\\Contracts\\Validation\\Rule', false)) {
            $methods = array_merge($methods, self::LEGACY_RULE_METHODS);
        }

        if ($this->classImplements($class, 'Illuminate\\Contracts\\Support\\Responsable')) {
            $methods = array_merge($methods, self::RESPONSABLE_METHODS);
        }

        // Console commands matched by exact base FQN ('\Command' is too common to suffix-match);
        // the path check in getContractMethodsToSkip() covers project-local base commands.
        if ($this->classExtends($class, 'Illuminate\\Console\\Command', false)) {
            $methods = array_merge($methods, self::CONSOLE_METHODS);
        }

        if ($this->classExtends($class, 'Illuminate\\Notifications\\Notification')) {
            $methods = array_merge($methods, self::NOTIFICATION_METHODS);
        }

        if ($this->classExtends($class, 'Illuminate\\Http\\Resources\\Json\\JsonResource')
            || $this->classExtends($class, 'Illuminate\\Http\\Resources\\Json\\ResourceCollection')) {
            $methods = array_merge($methods, self::JSON_RESOURCE_METHODS);
        }

        if ($this->extendsFilamentBase($class) || $this->isFilamentNamespace($namespace)) {
            $methods = array_merge($methods, self::FILAMENT_OVERRIDES);
        }

        return $methods;
    }

    /**
     * Check if a class extends Illuminate\Mail\Mailable (or a project-local Mailable base).
     */
    private function extendsMailable(Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $parent = ltrim($class->extends->toString(), '\\');

        return $parent === 'Illuminate\\Mail\\Mailable' || str_ends_with($parent, '\\Mailable');
    }

    /**
     * Check if a class extends Illuminate\Foundation\Http\FormRequest (or a local FormRequest base).
     */
    private function extendsFormRequest(Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $parent = ltrim($class->extends->toString(), '\\');

        return $parent === 'Illuminate\\Foundation\\Http\\FormRequest' || str_ends_with($parent, '\\FormRequest');
    }

    /**
     * Check if a class implements the ShouldQueue contract (queued job).
     */
    private function implementsShouldQueue(Stmt\Class_ $class): bool
    {
        foreach ($class->implements as $interface) {
            $name = ltrim($interface->toString(), '\\');
            if ($name === 'Illuminate\\Contracts\\Queue\\ShouldQueue' || str_ends_with($name, '\\ShouldQueue')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a class implements the Eloquent Scope contract (global scope).
     */
    private function implementsScope(Stmt\Class_ $class): bool
    {
        foreach ($class->implements as $interface) {
            $name = ltrim($interface->toString(), '\\');
            if ($name === 'Illuminate\\Database\\Eloquent\\Scope' || str_ends_with($name, '\\Scope')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a class implements the given interface — by exact FQN, and (when allowed)
     * by matching short name to catch project-local re-exports / aliased imports.
     */
    private function classImplements(Stmt\Class_ $class, string $interface, bool $allowSuffix = true): bool
    {
        $suffix = strrchr($interface, '\\');

        foreach ($class->implements as $impl) {
            $name = ltrim($impl->toString(), '\\');
            if ($name === $interface || ($allowSuffix && $suffix !== false && str_ends_with($name, $suffix))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a class extends the given base class — by exact FQN, and (when allowed)
     * by matching short name to catch project-local intermediate base classes.
     */
    private function classExtends(Stmt\Class_ $class, string $parent, bool $allowSuffix = true): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $name = ltrim($class->extends->toString(), '\\');
        $suffix = strrchr($parent, '\\');

        return $name === $parent || ($allowSuffix && $suffix !== false && str_ends_with($name, $suffix));
    }

    /**
     * Check if a file is an HTTP controller (by location or filename). Controllers are
     * exempt wholesale — every public method is a route action whose typed signature is
     * the documentation, so a docblock would only restate it.
     */
    private function isControllerFile(string $file): bool
    {
        return str_contains($file, '/Http/Controllers/') || str_ends_with($file, 'Controller.php');
    }

    /**
     * Check if a namespace places a class under Jobs or Listeners.
     */
    private function isJobOrListenerNamespace(?string $namespace): bool
    {
        if ($namespace === null) {
            return false;
        }

        return str_contains($namespace, '\\Jobs') || str_starts_with($namespace, 'Jobs')
            || str_contains($namespace, '\\Listeners') || str_starts_with($namespace, 'Listeners');
    }

    /**
     * Check if a namespace places a class under Http\Middleware (catches HTTP middleware,
     * which — like Laravel 11+ controllers — extend no base class).
     */
    private function isMiddlewareNamespace(?string $namespace): bool
    {
        if ($namespace === null) {
            return false;
        }

        return str_contains($namespace, '\\Http\\Middleware') || str_starts_with($namespace, 'Http\\Middleware');
    }

    /**
     * Check if a class extends a Filament base class.
     *
     * After NameResolver has been applied, the parent class name is FQN, so any parent
     * in the Filament\ namespace (e.g. Filament\Resources\Resource, Filament\PanelProvider)
     * marks a Filament UI class.
     */
    private function extendsFilamentBase(Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $parent = ltrim($class->extends->toString(), '\\');

        return str_starts_with($parent, 'Filament\\');
    }

    /**
     * Check if a namespace is a Filament namespace (e.g. App\Filament\Resources).
     */
    private function isFilamentNamespace(?string $namespace): bool
    {
        if ($namespace === null) {
            return false;
        }

        return str_starts_with($namespace, 'Filament\\')
            || str_contains($namespace, '\\Filament\\');
    }

    /**
     * Build a recommendation tailored to what the method actually needs.
     *
     * The guidance only mentions the tags the method genuinely requires: @param when a
     * parameter is untyped or generic, @return when the return type is ambiguous, @throws
     * when the body throws. A fully-typed method with no throws is simply asked for a
     * one-line summary, rather than the old blanket "@param/@return/@throws" checklist
     * that contradicted the analyzer's own self-documenting-type rules.
     */
    private function getRecommendation(string $type, string $method, bool $needsParam, bool $needsReturn, bool $needsThrows): string
    {
        $guidelines = match ($type) {
            'missing_param' => [
                "Add @param tags documenting each parameter of '{$method}' and its type",
            ],
            'missing_return' => [
                "Add a @return tag describing what '{$method}' returns",
            ],
            'missing_throws' => [
                "Add @throws tags for the exceptions '{$method}' may throw",
            ],
            default => $this->missingDocBlockGuidelines($method, $needsParam, $needsReturn, $needsThrows),
        };

        $base = match ($type) {
            'missing' => "The method '{$method}' has no PHPDoc comment. ",
            'missing_param' => "The method '{$method}' is missing @param tags. ",
            'missing_return' => "The method '{$method}' is missing a @return tag. ",
            'missing_throws' => "The method '{$method}' may throw exceptions but has no @throws tags. ",
            default => "The method '{$method}' has incomplete documentation. ",
        };

        return $base.'Documentation guidelines: '.implode('; ', $guidelines);
    }

    /**
     * Guidelines for a method with no DocBlock at all — tailored to its signature.
     *
     * @return array<string>
     */
    private function missingDocBlockGuidelines(string $method, bool $needsParam, bool $needsReturn, bool $needsThrows): array
    {
        $guidelines = ['Add a PHPDoc block with a short description of what the method does'];

        if ($needsParam) {
            $guidelines[] = 'Document each parameter with a @param tag and its type';
        }

        if ($needsReturn) {
            $guidelines[] = 'Document the return value with a @return tag';
        }

        if ($needsThrows) {
            $guidelines[] = 'Document thrown exceptions with @throws tags';
        }

        return $guidelines;
    }
}

/**
 * Visitor to detect missing or incomplete DocBlocks.
 */
class DocBlockVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{message: string, line: int, type: string, method: string, class: string, needsParam?: bool, needsReturn?: bool, needsThrows?: bool}>
     */
    private array $issues = [];

    /**
     * Current class name.
     */
    private ?string $currentClass = null;

    /**
     * @param  array<string>  $excludePatterns
     * @param  array<string>  $contractMethods  lowercased framework-contract method names to skip
     */
    public function __construct(
        private array $excludePatterns = [],
        private bool $requireTags = true,
        private array $contractMethods = []
    ) {}

    public function enterNode(Node $node)
    {
        // Track current class context (classes, traits, interfaces, and enums)
        if ($node instanceof Stmt\Class_ || $node instanceof Stmt\Trait_ || $node instanceof Stmt\Interface_ || $node instanceof Stmt\Enum_) {
            $this->currentClass = $node->name ? $node->name->toString() : 'Anonymous';

            return null;
        }

        // Check public methods
        if ($node instanceof Stmt\ClassMethod && $node->isPublic()) {
            $methodName = $node->name->toString();

            // Skip excluded patterns
            if ($this->shouldExclude($methodName)) {
                return null;
            }

            // Skip magic methods
            if (str_starts_with($methodName, '__')) {
                return null;
            }

            // Skip framework-contract methods (Mailable/FormRequest/Controller/Job/Listener/Filament)
            // whose signature and meaning are fixed by the framework. Gated by class type in the
            // analyzer so identically-named methods in plain classes stay flagged.
            if (in_array(strtolower($methodName), $this->contractMethods, true)) {
                return null;
            }

            // Skip trivially self-documenting methods: a trivial body (a single statement,
            // or assignments feeding a single return) whose typed signature already carries
            // everything a docblock would — no params needing docs, a self-documenting return
            // type, and no throws. Forcing a docblock here only invites a summary that
            // restates the signature — e.g. `label(): string` or `id(): ?int`.
            if ($this->isTriviallySelfDocumenting($node)) {
                return null;
            }

            $docComment = $node->getDocComment();

            // Check if method has no DocBlock
            if ($docComment === null) {
                $this->issues[] = [
                    'message' => "Public method '{$methodName}' has no PHPDoc comment",
                    'line' => $node->getStartLine(),
                    'type' => 'missing',
                    'method' => $methodName,
                    'class' => $this->currentClass ?? 'Unknown',
                    'needsParam' => $this->hasParamsRequiringDocs($node),
                    'needsReturn' => $this->returnRequiresDocs($node),
                    'needsThrows' => $this->mightThrowException($node),
                ];

                return null;
            }

            // Check DocBlock completeness if required
            if ($this->requireTags) {
                $this->checkDocBlockCompleteness($node, $methodName, $docComment);
            }
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        // Clear class context on exit
        if ($node instanceof Stmt\Class_ || $node instanceof Stmt\Trait_ || $node instanceof Stmt\Interface_ || $node instanceof Stmt\Enum_) {
            $this->currentClass = null;
        }

        return null;
    }

    /**
     * Check if method name matches exclude patterns.
     */
    private function shouldExclude(string $methodName): bool
    {
        foreach ($this->excludePatterns as $pattern) {
            // Convert glob pattern to regex (escape special chars, then replace * with .*)
            $escaped = preg_quote($pattern, '/');
            $regex = '/^'.str_replace('\\*', '.*', $escaped).'$/i';
            if (preg_match($regex, $methodName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if DocBlock has all required tags.
     */
    private function checkDocBlockCompleteness(Stmt\ClassMethod $node, string $methodName, Doc $docComment): void
    {
        $docText = $docComment->getText();

        // Check for @param tags if method has parameters with generic types
        if (! empty($node->params)) {
            // Count parameters that require documentation (generic types or no type)
            $paramsRequiringDocs = [];
            foreach ($node->params as $param) {
                if ($param->type === null || $this->isGenericType($param->type)) {
                    $paramName = $param->var->name ?? 'unknown';
                    $paramsRequiringDocs[] = $paramName;
                }
            }

            if (! empty($paramsRequiringDocs)) {
                // Count actual @param tags in docblock
                $paramTagCount = preg_match_all('/@param\b/i', $docText, $matches);

                // If we have fewer @param tags than parameters requiring documentation
                if ($paramTagCount < count($paramsRequiringDocs)) {
                    $missing = count($paramsRequiringDocs) - $paramTagCount;
                    $this->issues[] = [
                        'message' => "Public method '{$methodName}' has {$missing} parameter(s) missing @param documentation (found {$paramTagCount}, need ".count($paramsRequiringDocs).')',
                        'line' => $node->getStartLine(),
                        'type' => 'missing_param',
                        'method' => $methodName,
                        'class' => $this->currentClass ?? 'Unknown',
                    ];
                }
            }
        }

        // Check for @return tag (no docs needed for self-documenting return types)
        if (! str_contains($docText, '@return') && $this->returnRequiresDocs($node)) {
            $this->issues[] = [
                'message' => "Public method '{$methodName}' is missing @return documentation",
                'line' => $node->getStartLine(),
                'type' => 'missing_return',
                'method' => $methodName,
                'class' => $this->currentClass ?? 'Unknown',
            ];
        }

        // Check for @throws tag if method might throw exceptions
        if ($this->mightThrowException($node) && ! str_contains($docText, '@throws')) {
            $this->issues[] = [
                'message' => "Public method '{$methodName}' may throw exceptions but has no @throws documentation",
                'line' => $node->getStartLine(),
                'type' => 'missing_throws',
                'method' => $methodName,
                'class' => $this->currentClass ?? 'Unknown',
            ];
        }
    }

    /**
     * A method is trivially self-documenting when a complete docblock would carry no
     * required information: a trivial body, every parameter explicitly typed with a
     * self-documenting type, a self-documenting return type, and no throws.
     */
    private function isTriviallySelfDocumenting(Stmt\ClassMethod $node): bool
    {
        return $this->hasTrivialBody($node)
            && ! $this->hasParamsRequiringDocs($node)
            && ! $this->returnRequiresDocs($node)
            && ! $this->mightThrowException($node);
    }

    /**
     * A body is "trivial" when a complete docblock would add nothing beyond the signature:
     *
     * - A bodyless declaration (interface or abstract method): there is no implementation,
     *   so a fully-typed signature is the entire contract. Generic/ambiguous signatures are
     *   still caught by the param/return checks in isTriviallySelfDocumenting().
     * - A single statement.
     * - A single `return` preceded only by local variable assignments that feed that return
     *   value — the common assign-then-return idiom (often forced by a `@var` type-narrowing
     *   hint under static analysis), e.g. `$x = query()->first(); return $x;`.
     *
     * Any other statement before the return (a side-effecting call, a conditional, a loop)
     * or an assignment whose variable never feeds the return makes the method non-trivial.
     */
    private function hasTrivialBody(Stmt\ClassMethod $node): bool
    {
        $stmts = $node->stmts;

        // Interface / abstract method declaration — no body to assess.
        if ($stmts === null) {
            return true;
        }

        if ($stmts === []) {
            return false;
        }

        if (count($stmts) === 1) {
            return true;
        }

        $return = $stmts[count($stmts) - 1];

        if (! $return instanceof Stmt\Return_ || $return->expr === null) {
            return false;
        }

        $preceding = array_slice($stmts, 0, -1);

        // Collect every variable referenced by the return value and by assignment values,
        // so we can verify each assigned variable actually feeds the return.
        $referenced = $this->referencedVariableNames($return->expr);
        $assignedVars = [];

        foreach ($preceding as $stmt) {
            if (! $stmt instanceof Stmt\Expression || ! $stmt->expr instanceof Expr\Assign) {
                return false;
            }

            $target = $stmt->expr->var;

            if (! $target instanceof Expr\Variable || ! is_string($target->name)) {
                return false;
            }

            $assignedVars[] = $target->name;
            $referenced = array_merge($referenced, $this->referencedVariableNames($stmt->expr->expr));
        }

        foreach ($assignedVars as $name) {
            if (! in_array($name, $referenced, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Collect the names of all variables referenced within an expression subtree.
     *
     * @return array<string>
     */
    private function referencedVariableNames(Node $node): array
    {
        $names = [];

        foreach ((new NodeFinder)->findInstanceOf($node, Expr\Variable::class) as $variable) {
            if (is_string($variable->name)) {
                $names[] = $variable->name;
            }
        }

        return $names;
    }

    /**
     * Check if any parameter is untyped or has a generic type (so it needs @param docs).
     */
    private function hasParamsRequiringDocs(Stmt\ClassMethod $node): bool
    {
        foreach ($node->params as $param) {
            if ($param->type === null || $this->isGenericType($param->type)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the return type is missing or ambiguous (so it needs a @return tag).
     */
    private function returnRequiresDocs(Stmt\ClassMethod $node): bool
    {
        return $node->returnType === null || $this->requiresReturnDocumentation($node->returnType);
    }

    /**
     * Check if a type requires documentation.
     *
     * Returns false only for scalar native types (void, string, int, bool, float, etc.)
     * which are self-documenting. Returns true for:
     * - Generic types (array, iterable, object, mixed, callable) - need to specify structure
     * - No type hint - definitely needs documentation
     */
    private function isGenericType(Node $typeNode): bool
    {
        // Scalars are self-documenting
        if ($typeNode instanceof Node\Identifier) {
            $scalarTypes = [
                'void', 'string', 'int', 'float', 'bool',
                'true', 'false', 'null', 'never',
            ];

            return ! in_array(strtolower($typeNode->toString()), $scalarTypes, true);
        }

        // Concrete class names are self-documenting
        if ($typeNode instanceof Node\Name) {
            return false;
        }

        // Nullable types: defer to inner type
        if ($typeNode instanceof Node\NullableType) {
            return $this->isGenericType($typeNode->type);
        }

        // Union types: require docs if any part is non-scalar or ambiguous
        if ($typeNode instanceof Node\UnionType) {
            foreach ($typeNode->types as $type) {
                if ($this->isGenericType($type)) {
                    return true;
                }
            }

            return false;
        }

        // Intersection types should be documented
        if ($typeNode instanceof Node\IntersectionType) {
            return true;
        }

        return true;
    }

    /**
     * Check if return type requires @return documentation.
     *
     * Require @return when:
     * - Return type is mixed
     * - Return type is array, iterable, callable, object (generic types)
     * - Return type is a union or intersection
     *
     * Do NOT require @return when:
     * - Return type is a scalar (string, int, float, bool, etc.)
     * - Return type is a concrete class (User, Response, BelongsToMany, etc.)
     * - Return type is void or never
     */
    private function requiresReturnDocumentation(Node $typeNode): bool
    {
        // Scalars and void/never don't need docs
        if ($typeNode instanceof Node\Identifier) {
            $selfDocumentingTypes = [
                'void', 'never', 'string', 'int', 'float', 'bool',
                'true', 'false', 'null',
            ];

            $typeName = strtolower($typeNode->toString());

            // Self-documenting types don't need @return
            if (in_array($typeName, $selfDocumentingTypes, true)) {
                return false;
            }

            // Generic types that DO need documentation
            $genericTypes = ['mixed', 'array', 'iterable', 'callable', 'object'];
            if (in_array($typeName, $genericTypes, true)) {
                return true;
            }

            return false;
        }

        // Concrete class names (User, Response, BelongsToMany) don't need docs
        if ($typeNode instanceof Node\Name) {
            return false;
        }

        // Nullable types: defer to inner type
        if ($typeNode instanceof Node\NullableType) {
            return $this->requiresReturnDocumentation($typeNode->type);
        }

        // Union types: require @return only if any member itself requires documentation
        // (e.g. string|array needs @return to document array shape, but Response|JsonResponse does not)
        if ($typeNode instanceof Node\UnionType) {
            foreach ($typeNode->types as $type) {
                if ($this->requiresReturnDocumentation($type)) {
                    return true;
                }
            }

            return false;
        }

        // Intersection types ALWAYS require documentation
        if ($typeNode instanceof Node\IntersectionType) {
            return true;
        }

        // Unknown type nodes require documentation
        return true;
    }

    /**
     * Check if method might throw exceptions.
     */
    private function mightThrowException(Stmt\ClassMethod $node): bool
    {
        if ($node->stmts === null) {
            return false;
        }

        return $this->hasThrowStatement($node->stmts);
    }

    /**
     * Recursively check for throw statements in statement list.
     *
     * @param  array<Stmt>  $stmts
     */
    private function hasThrowStatement(array $stmts): bool
    {
        foreach ($stmts as $stmt) {
            // Throw expression (PHP 8+)
            if ($stmt instanceof Expr\Throw_) {
                return true;
            }

            // Throw expression wrapped in Expression statement (PHP 8+)
            if ($stmt instanceof Stmt\Expression && $stmt->expr instanceof Expr\Throw_) {
                return true;
            }

            // Check nested blocks
            if ($stmt instanceof Stmt\If_) {
                if ($this->hasThrowStatement($stmt->stmts)) {
                    return true;
                }
                foreach ($stmt->elseifs as $elseif) {
                    if ($this->hasThrowStatement($elseif->stmts)) {
                        return true;
                    }
                }
                if ($stmt->else !== null && $this->hasThrowStatement($stmt->else->stmts)) {
                    return true;
                }
            } elseif ($stmt instanceof Stmt\While_) {
                if ($this->hasThrowStatement($stmt->stmts)) {
                    return true;
                }
            } elseif ($stmt instanceof Stmt\Do_) {
                if ($this->hasThrowStatement($stmt->stmts)) {
                    return true;
                }
            } elseif ($stmt instanceof Stmt\For_) {
                if ($this->hasThrowStatement($stmt->stmts)) {
                    return true;
                }
            } elseif ($stmt instanceof Stmt\Foreach_) {
                if ($this->hasThrowStatement($stmt->stmts)) {
                    return true;
                }
            } elseif ($stmt instanceof Stmt\Switch_) {
                foreach ($stmt->cases as $case) {
                    if ($this->hasThrowStatement($case->stmts)) {
                        return true;
                    }
                }
            } elseif ($stmt instanceof Stmt\TryCatch) {
                // Don't check try block - exceptions there are caught and handled internally
                // Only check catch blocks (for re-throws or new throws) and finally block

                // Check catch blocks for re-throws or new throws
                foreach ($stmt->catches as $catch) {
                    if ($this->hasThrowStatement($catch->stmts)) {
                        return true;
                    }
                }
                // Check finally block
                if ($stmt->finally !== null && $this->hasThrowStatement($stmt->finally->stmts)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{message: string, line: int, type: string, method: string, class: string}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
