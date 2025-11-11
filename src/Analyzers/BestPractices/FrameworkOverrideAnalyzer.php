<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\BestPractices;

use PhpParser\Node;
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
 * Detects overriding standard Laravel framework classes.
 */
class FrameworkOverrideAnalyzer extends AbstractFileAnalyzer
{
    public function __construct(
        private ParserInterface $parser
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'framework-override',
            name: 'Framework Override Detector',
            description: 'Detects dangerous overrides of Laravel framework classes',
            category: Category::BestPractices,
            severity: Severity::High,
            tags: ['laravel', 'framework', 'upgradability', 'maintenance'],
            docsUrl: 'https://docs.shieldci.com/analyzers/framework-override',
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];
        $phpFiles = $this->getPhpFiles();

        foreach ($phpFiles as $file) {
            try {
                $ast = $this->parser->parseFile($file);
                if (empty($ast)) {
                    continue;
                }

                $visitor = new FrameworkOverrideVisitor;
                $traverser = new NodeTraverser;
                $traverser->addVisitor($visitor);
                $traverser->traverse($ast);

                foreach ($visitor->getIssues() as $issue) {
                    $issues[] = $this->createIssue(
                        message: $issue['message'],
                        location: new Location($this->getRelativePath($file), $issue['line']),
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
            return $this->passed('No dangerous framework overrides detected');
        }

        return $this->failed(
            sprintf('Found %d framework override(s)', count($issues)),
            $issues
        );
    }
}

class FrameworkOverrideVisitor extends NodeVisitorAbstract
{
    private array $issues = [];

    // Core Laravel classes that should rarely be extended
    private array $coreFrameworkClasses = [
        'Illuminate\\Http\\Request',
        'Illuminate\\Http\\Response',
        'Illuminate\\Http\\RedirectResponse',
        'Illuminate\\Http\\JsonResponse',
        'Illuminate\\Routing\\Router',
        'Illuminate\\Foundation\\Application',
        'Illuminate\\Database\\Eloquent\\Builder',
        'Illuminate\\Database\\Query\\Builder',
        'Illuminate\\Support\\Facades\\Facade',
    ];

    public function enterNode(Node $node): ?Node
    {
        if ($node instanceof Node\Stmt\Class_) {
            if ($node->extends !== null) {
                $parentClass = $node->extends->toString();

                // Check if extending a core framework class
                if ($this->isCoreFrameworkClass($parentClass)) {
                    $className = $node->name?->toString() ?? 'Unknown';

                    $this->issues[] = [
                        'message' => sprintf(
                            'Class "%s" extends core framework class "%s"',
                            $className,
                            $parentClass
                        ),
                        'line' => $node->getLine(),
                        'severity' => Severity::High,
                        'recommendation' => sprintf(
                            'Avoid extending core framework classes. Use Laravel\'s extension points instead: '.
                            'macros (e.g., Request::macro()), service providers, middleware, or event listeners. '.
                            'Extending core classes will break during framework upgrades. '.
                            'For %s, consider using middleware or macros instead.',
                            $this->getShortClassName($parentClass)
                        ),
                        'code' => null,
                    ];
                }
            }
        }

        return null;
    }

    private function isCoreFrameworkClass(string $className): bool
    {
        foreach ($this->coreFrameworkClasses as $coreClass) {
            if ($className === $coreClass || str_ends_with($coreClass, '\\'.$className)) {
                return true;
            }
        }

        return false;
    }

    private function getShortClassName(string $fullClassName): string
    {
        $parts = explode('\\', $fullClassName);

        return end($parts);
    }

    public function getIssues(): array
    {
        return $this->issues;
    }
}
