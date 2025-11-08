<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Detects env() calls outside of configuration files.
 *
 * Checks for:
 * - env() function calls in controllers, models, services
 * - env() calls that will break when config is cached
 * - Recommends using config() instead of env()
 */
class EnvCallAnalyzer extends AbstractFileAnalyzer
{
    private AstParser $parser;

    public function __construct()
    {
        $this->parser = new AstParser;
    }

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
        $issues = [];

        // Set paths to analyze (exclude config directory)
        $this->setPaths(['app', 'routes', 'database', 'resources/views']);

        foreach ($this->getPhpFiles() as $file) {
            $filePath = $file instanceof \SplFileInfo ? $file->getPathname() : (string) $file;

            // Skip config files
            if (str_contains($filePath, '/config/')) {
                continue;
            }

            try {
                $ast = $this->parser->parseFile($filePath);
                $this->analyzeFile($filePath, $ast, $issues);
            } catch (\Throwable $e) {
                // Skip files that can't be parsed
                continue;
            }
        }

        if (empty($issues)) {
            return $this->passed('No env() calls detected outside configuration files');
        }

        return $this->failed(
            sprintf('Found %d env() calls outside configuration files', count($issues)),
            $issues
        );
    }

    private function analyzeFile(string $filePath, array $ast, array &$issues): void
    {
        $nodeFinder = new NodeFinder;

        // Find all function calls
        $functionCalls = $nodeFinder->findInstanceOf($ast, FuncCall::class);

        foreach ($functionCalls as $funcCall) {
            if ($funcCall->name instanceof Name && $funcCall->name->toString() === 'env') {
                // Get the env variable name if it's a string literal
                $varName = null;

                if (isset($funcCall->args[0]) && $funcCall->args[0]->value instanceof Node\Scalar\String_) {
                    $varName = $funcCall->args[0]->value->value;
                }

                $issues[] = $this->createIssue(
                    message: 'env() call detected outside configuration files',
                    location: new Location($filePath, $funcCall->getLine()),
                    severity: Severity::High,
                    recommendation: $this->getRecommendation($varName),
                    code: $this->getCodeSnippet($filePath, $funcCall->getLine()),
                    metadata: [
                        'function' => 'env',
                        'variable' => $varName,
                        'file_type' => $this->getFileType($filePath),
                    ]
                );
            }
        }
    }

    private function getRecommendation(?string $varName): string
    {
        $base = 'Do not call env() outside of configuration files. Once config is cached (php artisan config:cache), the .env file is not loaded and env() returns null. ';

        if ($varName) {
            $configKey = $this->suggestConfigKey($varName);

            return $base."Add '{$varName}' to a config file (e.g., config/{$configKey[0]}.php) and use config('{$configKey[1]}') instead of env('{$varName}').";
        }

        return $base.'Move this env() call to a configuration file and use config() to retrieve the value instead.';
    }

    private function suggestConfigKey(string $varName): array
    {
        // Suggest appropriate config file and key based on env variable name
        $varLower = strtolower($varName);

        if (str_starts_with($varLower, 'app_')) {
            return ['app', 'app.'.strtolower(substr($varName, 4))];
        }

        if (str_starts_with($varLower, 'db_') || str_starts_with($varLower, 'database_')) {
            return ['database', 'database.'.strtolower(str_replace(['DB_', 'DATABASE_'], '', $varName))];
        }

        if (str_starts_with($varLower, 'cache_')) {
            return ['cache', 'cache.'.strtolower(substr($varName, 6))];
        }

        if (str_starts_with($varLower, 'mail_')) {
            return ['mail', 'mail.'.strtolower(substr($varName, 5))];
        }

        if (str_starts_with($varLower, 'queue_')) {
            return ['queue', 'queue.'.strtolower(substr($varName, 6))];
        }

        if (str_starts_with($varLower, 'session_')) {
            return ['session', 'session.'.strtolower(substr($varName, 8))];
        }

        // Default to custom config file
        return ['custom', 'custom.'.strtolower($varName)];
    }

    private function getFileType(string $filePath): string
    {
        if (str_contains($filePath, '/app/Http/Controllers/')) {
            return 'controller';
        }

        if (str_contains($filePath, '/app/Models/')) {
            return 'model';
        }

        if (str_contains($filePath, '/app/Services/')) {
            return 'service';
        }

        if (str_contains($filePath, '/routes/')) {
            return 'route';
        }

        if (str_contains($filePath, '/resources/views/')) {
            return 'view';
        }

        return 'application';
    }
}
