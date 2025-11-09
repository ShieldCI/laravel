<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\CodeQuality;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ParserInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Identifies excessively large classes.
 *
 * Checks for:
 * - Classes exceeding line count threshold
 * - Classes with too many methods
 * - Classes with too many properties
 * - God objects that do too much
 */
class ClassLengthAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Maximum lines of code for a class.
     */
    private int $maxLines = 300;

    /**
     * Maximum number of methods in a class.
     */
    private int $maxMethods = 20;

    /**
     * Maximum number of properties in a class.
     */
    private int $maxProperties = 15;

    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'class-length',
            name: 'Class Length',
            description: 'Identifies excessively large classes that should be refactored into smaller, focused components',
            category: Category::CodeQuality,
            severity: Severity::Medium,
            tags: ['complexity', 'maintainability', 'code-quality', 'srp', 'god-object'],
            docsUrl: 'https://refactoring.guru/smells/large-class'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $maxLines = $this->maxLines;
        $maxMethods = $this->maxMethods;
        $maxProperties = $this->maxProperties;

        foreach ($this->getPhpFiles() as $file) {
            $ast = $this->parser->parseFile($file);

            if (empty($ast)) {
                continue;
            }

            $visitor = new ClassLengthVisitor($maxLines, $maxMethods, $maxProperties);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            foreach ($visitor->getIssues() as $issue) {
                $issues[] = $this->createIssue(
                    message: $this->getMessage($issue),
                    location: new Location($file, $issue['line']),
                    severity: $this->getSeverityForClass($issue, $maxLines, $maxMethods, $maxProperties),
                    recommendation: $this->getRecommendation($issue),
                    metadata: [
                        'class' => $issue['class'],
                        'lines' => $issue['lines'],
                        'methods' => $issue['methods'],
                        'properties' => $issue['properties'],
                        'violations' => $issue['violations'],
                        'file' => $file,
                    ]
                );
            }
        }

        if (empty($issues)) {
            return $this->passed('All classes are within recommended size limits');
        }

        $totalIssues = count($issues);

        return $this->failed(
            "Found {$totalIssues} oversized class(es)",
            $issues
        );
    }

    /**
     * Get message for class size issue.
     *
     * @param  array{class: string, lines: int, methods: int, properties: int, violations: array<string>}  $issue
     */
    private function getMessage(array $issue): string
    {
        $violations = implode(', ', $issue['violations']);

        return "Class '{$issue['class']}' is too large: {$violations} (lines: {$issue['lines']}, methods: {$issue['methods']}, properties: {$issue['properties']})";
    }

    /**
     * Get severity based on how much the class exceeds limits.
     *
     * @param  array{class: string, lines: int, methods: int, properties: int, violations: array<string>}  $issue
     */
    private function getSeverityForClass(array $issue, int $maxLines, int $maxMethods, int $maxProperties): Severity
    {
        $violationCount = count($issue['violations']);
        $lineExcess = max(0, $issue['lines'] - $maxLines);
        $methodExcess = max(0, $issue['methods'] - $maxMethods);

        // Multiple severe violations = high severity
        if ($violationCount >= 3 || $lineExcess > 300 || $methodExcess > 15) {
            return Severity::High;
        }

        // Moderate excess = medium severity
        if ($violationCount >= 2 || $lineExcess > 150 || $methodExcess > 10) {
            return Severity::Medium;
        }

        return Severity::Low;
    }

    /**
     * Get recommendation for oversized class.
     *
     * @param  array{class: string, lines: int, methods: int, properties: int, violations: array<string>}  $issue
     */
    private function getRecommendation(array $issue): string
    {
        $base = "Class '{$issue['class']}' has {$issue['lines']} lines, {$issue['methods']} methods, and {$issue['properties']} properties. Large classes violate the Single Responsibility Principle and are harder to understand, test, and maintain. ";

        $strategies = [
            'Extract related methods and properties into separate classes',
            'Identify distinct responsibilities and create focused classes for each',
            'Use composition over inheritance to delegate functionality',
            'Extract data structures into Value Objects or DTOs',
            'Move related methods to service classes or traits',
            'Apply the Single Responsibility Principle - each class should have one reason to change',
            'Consider using the Strategy, Decorator, or Facade patterns',
        ];

        $example = <<<'PHP'

// Problem - God object with multiple responsibilities:
class UserManager
{
    // User CRUD (80 lines)
    public function createUser() { /* ... */ }
    public function updateUser() { /* ... */ }
    public function deleteUser() { /* ... */ }

    // Authentication (60 lines)
    public function login() { /* ... */ }
    public function logout() { /* ... */ }
    public function verifyPassword() { /* ... */ }

    // Email notifications (50 lines)
    public function sendWelcomeEmail() { /* ... */ }
    public function sendPasswordReset() { /* ... */ }

    // Reporting (40 lines)
    public function generateUserReport() { /* ... */ }
    public function exportUserData() { /* ... */ }

    // 15+ more methods, 20+ properties...
    // Total: 300+ lines
}

// Solution - Split into focused classes:

class UserRepository
{
    public function create(array $data): User { /* ... */ }
    public function update(User $user, array $data): void { /* ... */ }
    public function delete(User $user): void { /* ... */ }
}

class AuthenticationService
{
    public function login(string $email, string $password): User { /* ... */ }
    public function logout(User $user): void { /* ... */ }
    public function verifyPassword(User $user, string $password): bool { /* ... */ }
}

class UserNotificationService
{
    public function sendWelcomeEmail(User $user): void { /* ... */ }
    public function sendPasswordReset(User $user): void { /* ... */ }
}

class UserReportGenerator
{
    public function generate(User $user): Report { /* ... */ }
    public function export(User $user, string $format): string { /* ... */ }
}

// Orchestrate via controller or service:
class UserService
{
    public function __construct(
        private UserRepository $users,
        private AuthenticationService $auth,
        private UserNotificationService $notifications
    ) {}

    public function registerUser(array $data): User
    {
        $user = $this->users->create($data);
        $this->notifications->sendWelcomeEmail($user);
        return $user;
    }
}
PHP;

        return $base.'Refactoring strategies: '.implode('; ', $strategies).". Example:{$example}";
    }
}

/**
 * Visitor to measure class size metrics.
 */
class ClassLengthVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<int, array{class: string, lines: int, methods: int, properties: int, violations: array<string>, line: int}>
     */
    private array $issues = [];

    public function __construct(
        private int $maxLines,
        private int $maxMethods,
        private int $maxProperties
    ) {}

    public function enterNode(Node $node)
    {
        // Analyze classes
        if ($node instanceof Stmt\Class_) {
            $className = $node->name ? $node->name->toString() : 'Anonymous';

            $metrics = $this->calculateClassMetrics($node);
            $violations = [];

            // Check line count
            if ($metrics['lines'] > $this->maxLines) {
                $violations[] = "{$metrics['lines']} lines (max: {$this->maxLines})";
            }

            // Check method count
            if ($metrics['methods'] > $this->maxMethods) {
                $violations[] = "{$metrics['methods']} methods (max: {$this->maxMethods})";
            }

            // Check property count
            if ($metrics['properties'] > $this->maxProperties) {
                $violations[] = "{$metrics['properties']} properties (max: {$this->maxProperties})";
            }

            // Report if any violations found
            if (! empty($violations)) {
                $this->issues[] = [
                    'class' => $className,
                    'lines' => $metrics['lines'],
                    'methods' => $metrics['methods'],
                    'properties' => $metrics['properties'],
                    'violations' => $violations,
                    'line' => $node->getStartLine(),
                ];
            }
        }

        return null;
    }

    /**
     * Calculate class metrics.
     *
     * @return array{lines: int, methods: int, properties: int}
     */
    private function calculateClassMetrics(Stmt\Class_ $node): array
    {
        $startLine = $node->getStartLine();
        $endLine = $node->getEndLine();
        $lines = $endLine - $startLine + 1;

        $methodCount = 0;
        $propertyCount = 0;

        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Stmt\ClassMethod) {
                $methodCount++;
            }

            if ($stmt instanceof Stmt\Property) {
                // Count each property variable
                $propertyCount += count($stmt->props);
            }
        }

        return [
            'lines' => $lines,
            'methods' => $methodCount,
            'properties' => $propertyCount,
        ];
    }

    /**
     * Get collected issues.
     *
     * @return array<int, array{class: string, lines: int, methods: int, properties: int, violations: array<string>, line: int}>
     */
    public function getIssues(): array
    {
        return $this->issues;
    }
}
