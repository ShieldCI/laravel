<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\InspectsCode;
use ShieldCI\Support\ConfigSuggester;
use ShieldCI\Support\FileTypeDetector;

/**
 * Detects env() calls outside of configuration files.
 *
 * Checks for:
 * - env() function calls in controllers, models, services
 * - env() calls that will break when config is cached
 * - Recommends using config() instead of env()
 *
 * Uses the InspectsCode trait for AST parsing abstraction.
 */
class EnvCallAnalyzer extends AbstractFileAnalyzer
{
    use InspectsCode;

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-call-outside-config',
            name: 'Env Calls Outside Config',
            description: 'Detects env() function calls outside configuration files that break when config is cached',
            category: Category::Performance,
            severity: Severity::High,
            tags: ['configuration', 'cache', 'performance', 'env'],
            docsUrl: 'https://laravel.com/docs/configuration#configuration-caching'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Find all env() function calls, excluding config directory
        $envCalls = $this->findFunctionCalls(
            functionName: 'env',
            paths: ['app', 'routes', 'database', 'resources/views'],
            excludePaths: ['/config/']
        );

        if (empty($envCalls)) {
            return $this->passed('No env() calls detected outside configuration files');
        }

        // Create issues for each env() call found
        $issues = [];

        foreach ($envCalls as $call) {
            $varName = $call['args'][0] ?? null;
            $filePath = $call['file'];
            $line = $call['node']->getLine();

            // Ensure varName is string|null for ConfigSuggester
            $varNameString = is_string($varName) ? $varName : null;

            $issues[] = $this->createIssue(
                message: 'env() call detected outside configuration files',
                location: new Location($filePath, $line),
                severity: Severity::High,
                recommendation: ConfigSuggester::getRecommendation($varNameString),
                code: $this->getCodeSnippet($filePath, $line),
                metadata: [
                    'function' => 'env',
                    'variable' => $varNameString,
                    'file_type' => FileTypeDetector::detect($filePath),
                ]
            );
        }

        return $this->failed(
            sprintf('Found %d env() calls outside configuration files', count($issues)),
            $issues
        );
    }
}
