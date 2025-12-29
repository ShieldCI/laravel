<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\CodeQuality\MethodLengthAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class MethodLengthAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'code-quality' => $config,
                ],
            ],
        ]);

        return new MethodLengthAnalyzer($this->parser, $configRepo);
    }

    #[Test]
    public function test_detects_long_methods(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class DataProcessor
{
    public function processData(\$input)
    {
{$statements}
        return \$var;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DataProcessor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('lines', $result);
    }

    #[Test]
    public function test_passes_with_short_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getName($user)
    {
        return $user->name ?? 'Unknown';
    }

    public function getEmail($user)
    {
        return $user->email;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_getter_methods(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class DataService
{
    // Getter should be excluded even if long
    public function getData()
    {
{$statements}
        return \$var;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DataService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because getters are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_setter_methods(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class DataService
{
    // Setter should be excluded even if long
    public function setConfiguration(\$config)
    {
{$statements}
        return \$var;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DataService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because setters are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_is_methods(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class ValidationService
{
    // is* methods should be excluded even if long
    public function isValid(\$data)
    {
{$statements}
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ValidationService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because is* methods are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_has_methods(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class FeatureService
{
    // has* methods should be excluded even if long
    public function hasPermission(\$user)
    {
{$statements}
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/FeatureService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because has* methods are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_method_at_exact_threshold_passes(): void
    {
        // Exactly 50 physical lines (at threshold, not over)
        // Method declaration + 47 statements + closing brace = 50 lines
        $statements = str_repeat('        $var = "value";'."\n", 47);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because we're at threshold, not over
        $this->assertPassed($result);
    }

    #[Test]
    public function test_method_at_threshold_plus_one_fails(): void
    {
        // 51 physical lines (threshold + 1)
        // Method declaration + 48 statements + closing brace = 51 lines
        $statements = str_repeat('        $var = "value";'."\n", 48);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should fail because we're over threshold
        $this->assertFailed($result);
    }

    #[Test]
    public function test_severity_is_low_for_moderate_length(): void
    {
        // 60 lines (1.2x threshold)
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::Low, $issues[0]->severity);
    }

    #[Test]
    public function test_severity_is_medium_for_excessive_length(): void
    {
        // 100 lines (2x threshold)
        $statements = str_repeat('        $var = "value";'."\n", 100);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::Medium, $issues[0]->severity);
    }

    #[Test]
    public function test_detects_long_standalone_functions(): void
    {
        $statements = str_repeat('    $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Helpers;

function processHelper(\$data)
{
{$statements}
    return \$var;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Helpers/helpers.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('processHelper', $result);
    }

    #[Test]
    public function test_handles_abstract_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

abstract class BaseService
{
    // Abstract method has no body, should not be flagged
    abstract public function process($data);

    public function helper()
    {
        return 'test';
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/BaseService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because abstract method has no statements
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_multiple_long_methods_in_one_file(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function firstMethod()
    {
{$statements}
        return \$var;
    }

    public function secondMethod()
    {
{$statements}
        return \$var;
    }

    public function shortMethod()
    {
        return 'short';
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $this->assertHasIssueContaining('firstMethod', $result);
        $this->assertHasIssueContaining('secondMethod', $result);
    }

    #[Test]
    public function test_includes_correct_metadata(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('name', $metadata);
        $this->assertArrayHasKey('type', $metadata);
        $this->assertArrayHasKey('lines', $metadata);
        $this->assertArrayHasKey('threshold', $metadata);
        $this->assertSame('process', $metadata['name']);
        $this->assertSame('method', $metadata['type']);
        $this->assertSame(50, $metadata['threshold']);
    }

    #[Test]
    public function test_recommendation_uses_configured_threshold(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 80);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer([
            'method-length' => [
                'threshold' => 75,
            ],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // Verify recommendation includes the configured threshold (75), not hardcoded "30-50 lines"
        $this->assertStringContainsString('Maximum recommended length: 75 lines', $issues[0]->recommendation);
    }

    #[Test]
    public function test_recommendation_uses_default_threshold(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // Verify recommendation includes the default threshold (50 lines)
        $this->assertStringContainsString('Maximum recommended length: 50 lines', $issues[0]->recommendation);
    }

    #[Test]
    public function test_differentiates_functions_from_methods(): void
    {
        $statements = str_repeat('    $var = "value";'."\n", 60);

        // Test with a global function
        $code = <<<PHP
<?php

function processData(\$data)
{
{$statements}
}

class Service
{
    public function processOrder(\$order)
    {
{$statements}
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/helpers.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);

        // Check global function uses "Function" wording
        $functionIssue = collect($issues)->first(fn ($issue) => $issue->metadata['type'] === 'function');
        $this->assertNotNull($functionIssue);
        $this->assertStringContainsString("Function 'processData'", $functionIssue->message);
        $this->assertStringContainsString('This function has', $functionIssue->recommendation);

        // Check class method uses "Method" wording
        $methodIssue = collect($issues)->first(fn ($issue) => $issue->metadata['type'] === 'method');
        $this->assertNotNull($methodIssue);
        $this->assertStringContainsString("Method 'processOrder'", $methodIssue->message);
        $this->assertStringContainsString('This method has', $methodIssue->recommendation);
    }

    #[Test]
    public function test_has_correct_analyzer_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('method-length', $metadata->id);
        $this->assertSame('Method Length Analyzer', $metadata->name);
        $this->assertContains('maintainability', $metadata->tags);
    }
}
