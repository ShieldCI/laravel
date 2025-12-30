<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\CodeQuality\NestingDepthAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Tests\AnalyzerTestCase;

class NestingDepthAnalyzerTest extends AnalyzerTestCase
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

        return new NestingDepthAnalyzer($this->parser, $configRepo);
    }

    #[Test]
    public function test_detects_deep_nesting_with_if_statements(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ValidationService
{
    public function validate($data)
    {
        if ($data) {
            if ($data['user']) {
                if ($data['user']['email']) {
                    if (filter_var($data['user']['email'], FILTER_VALIDATE_EMAIL)) {
                        if ($data['user']['age'] > 18) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('nesting depth', $result);
    }

    #[Test]
    public function test_passes_with_guard_clauses(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ValidationService
{
    public function validate($data)
    {
        if (!$data) {
            return false;
        }

        if (!isset($data['user'])) {
            return false;
        }

        if (!isset($data['user']['email'])) {
            return false;
        }

        return filter_var($data['user']['email'], FILTER_VALIDATE_EMAIL);
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

        $this->assertPassed($result);
    }

    #[Test]
    public function test_elseif_and_else_do_not_add_nesting_levels(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Test
{
    public function check($status)
    {
        if ($status === 'active') {
            return 'active';
        } elseif ($status === 'pending') {
            return 'pending';
        } elseif ($status === 'inactive') {
            return 'inactive';
        } else {
            return 'unknown';
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - elseif and else don't add nesting depth
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_deep_nesting_with_foreach_loops(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Processor
{
    public function process($items)
    {
        foreach ($items as $item) {
            foreach ($item['children'] as $child) {
                foreach ($child['data'] as $data) {
                    foreach ($data['values'] as $value) {
                        foreach ($value['props'] as $prop) {
                            // Depth 5 - should fail
                            echo $prop;
                        }
                    }
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Processor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('nesting depth', $result);
    }

    #[Test]
    public function test_detects_deep_nesting_with_while_loops(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Worker
{
    public function work()
    {
        while ($condition1) {
            while ($condition2) {
                while ($condition3) {
                    while ($condition4) {
                        while ($condition5) {
                            // Depth 5
                            doWork();
                        }
                    }
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Worker.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('nesting depth', $result);
    }

    #[Test]
    public function test_detects_deep_nesting_with_for_loops(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Calculator
{
    public function calculate()
    {
        for ($i = 0; $i < 10; $i++) {
            for ($j = 0; $j < 10; $j++) {
                for ($k = 0; $k < 10; $k++) {
                    for ($l = 0; $l < 10; $l++) {
                        for ($m = 0; $m < 10; $m++) {
                            // Depth 5
                            compute($i, $j, $k, $l, $m);
                        }
                    }
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Calculator.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('nesting depth', $result);
    }

    #[Test]
    public function test_try_catch_does_not_add_extra_nesting(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Handler
{
    public function handle()
    {
        try {
            doSomething();
        } catch (\Exception $e) {
            log($e);
        } catch (\Error $e) {
            log($e);
        } catch (\Throwable $e) {
            log($e);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Handler.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - try-catch is only depth 1, multiple catch blocks don't add nesting
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_deep_nesting_in_try_catch(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class ErrorHandler
{
    public function process()
    {
        try {
            if ($a) {
                if ($b) {
                    if ($c) {
                        if ($d) {
                            if ($e) {
                                // Depth 6 (try + 5 ifs)
                                doSomething();
                            }
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            log($e);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/ErrorHandler.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('nesting depth', $result);
    }

    #[Test]
    public function test_detects_deep_nesting_in_switch_statement(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Router
{
    public function route($type)
    {
        switch ($type) {
            case 'admin':
                if ($user) {
                    if ($user->isAdmin()) {
                        if ($user->isActive()) {
                            if ($user->hasPermission('access')) {
                                // Depth 5 (switch + case + 3 ifs)
                                return true;
                            }
                        }
                    }
                }
                break;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Router.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('nesting depth', $result);
    }

    #[Test]
    public function test_detects_mixed_nesting_types(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Mixer
{
    public function mix()
    {
        if ($a) {
            foreach ($items as $item) {
                try {
                    while ($condition) {
                        for ($i = 0; $i < 10; $i++) {
                            // Depth 5
                            process($item, $i);
                        }
                    }
                } catch (\Exception $e) {
                    log($e);
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Mixer.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('nesting depth', $result);
    }

    #[Test]
    public function test_depth_exactly_at_threshold(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Boundary
{
    public function test()
    {
        if ($a) {
            if ($b) {
                if ($c) {
                    if ($d) {
                        // Exactly depth 4 - should pass
                        return true;
                    }
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Boundary.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - depth 4 is at threshold, not exceeding
        $this->assertPassed($result);
    }

    #[Test]
    public function test_depth_one_above_threshold(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class OverThreshold
{
    public function test()
    {
        if ($a) {
            if ($b) {
                if ($c) {
                    if ($d) {
                        if ($e) {
                            // Depth 5 - exceeds threshold
                            return true;
                        }
                    }
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/OverThreshold.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('nesting depth of 5', $result);
    }

    #[Test]
    public function test_handles_nested_closures(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class ClosureTest
{
    public function test()
    {
        if ($a) {
            if ($b) {
                $callback = function() {
                    // Closure resets depth - depth 0 inside closure
                    if ($c) {
                        if ($d) {
                            // Depth 2 inside closure - should pass
                            return true;
                        }
                    }
                };
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/ClosureTest.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - closure resets depth
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_deep_nesting_inside_closure(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class DeepClosure
{
    public function test()
    {
        $callback = function() {
            if ($a) {
                if ($b) {
                    if ($c) {
                        if ($d) {
                            if ($e) {
                                // Depth 5 inside closure
                                return true;
                            }
                        }
                    }
                }
            }
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/DeepClosure.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('nesting depth', $result);
    }

    #[Test]
    public function test_tracks_multiple_methods_separately(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class MultiMethod
{
    public function goodMethod()
    {
        if ($a) {
            return true;
        }
        return false;
    }

    public function badMethod()
    {
        if ($a) {
            if ($b) {
                if ($c) {
                    if ($d) {
                        if ($e) {
                            // Depth 5
                            return true;
                        }
                    }
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/MultiMethod.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        // Only badMethod should have issues
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertIsString($issues[0]->metadata['context']);
        $this->assertStringContainsString('badMethod', (string) $issues[0]->metadata['context']);
    }

    #[Test]
    public function test_do_while_loop_nesting(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class DoWhile
{
    public function process()
    {
        do {
            do {
                do {
                    do {
                        do {
                            // Depth 5
                            work();
                        } while ($e);
                    } while ($d);
                } while ($c);
            } while ($b);
        } while ($a);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/DoWhile.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('nesting depth', $result);
    }

    #[Test]
    public function test_severity_levels(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class SeverityTest
{
    public function lowSeverity()
    {
        if ($a) {
            if ($b) {
                if ($c) {
                    if ($d) {
                        if ($e) {
                            // Depth 5 (threshold + 1) = Low severity
                            return 'low';
                        }
                    }
                }
            }
        }
    }

    public function mediumSeverity()
    {
        if ($a) {
            if ($b) {
                if ($c) {
                    if ($d) {
                        if ($e) {
                            if ($f) {
                                // Depth 6 (threshold + 2) = Medium severity
                                return 'medium';
                            }
                        }
                    }
                }
            }
        }
    }

    public function highSeverity()
    {
        if ($a) {
            if ($b) {
                if ($c) {
                    if ($d) {
                        if ($e) {
                            if ($f) {
                                if ($g) {
                                    // Depth 7 (threshold + 3) = High severity
                                    return 'high';
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/SeverityTest.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(3, count($issues));

        // Check severity levels - find the deepest nesting in each method
        $lowIssue = null;
        $mediumIssue = null;
        $highIssue = null;

        foreach ($issues as $issue) {
            $context = $issue->metadata['context'];
            $depth = $issue->metadata['depth'];

            if ($context === 'lowSeverity' && (! $lowIssue || $depth > $lowIssue->metadata['depth'])) {
                $lowIssue = $issue;
            } elseif ($context === 'mediumSeverity' && (! $mediumIssue || $depth > $mediumIssue->metadata['depth'])) {
                $mediumIssue = $issue;
            } elseif ($context === 'highSeverity' && (! $highIssue || $depth > $highIssue->metadata['depth'])) {
                $highIssue = $issue;
            }
        }

        $this->assertNotNull($lowIssue);
        $this->assertNotNull($mediumIssue);
        $this->assertNotNull($highIssue);

        $this->assertEquals(5, $lowIssue->metadata['depth']);
        $this->assertEquals(6, $mediumIssue->metadata['depth']);
        $this->assertEquals(7, $highIssue->metadata['depth']);

        $this->assertEquals(Severity::Low, $lowIssue->severity);
        $this->assertEquals(Severity::Medium, $mediumIssue->severity);
        $this->assertEquals(Severity::High, $highIssue->severity);
    }

    #[Test]
    public function test_includes_correct_metadata(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class MetadataTest
{
    public function testMethod()
    {
        if ($a) {
            if ($b) {
                if ($c) {
                    if ($d) {
                        if ($e) {
                            return true;
                        }
                    }
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/MetadataTest.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $issue = $issues[0];
        $metadata = $issue->metadata;

        $this->assertArrayHasKey('depth', $metadata);
        $this->assertArrayHasKey('threshold', $metadata);
        $this->assertArrayHasKey('context', $metadata);
        $this->assertEquals(5, $metadata['depth']);
        $this->assertEquals(4, $metadata['threshold']);
        $this->assertEquals('testMethod', $metadata['context']);
    }

    #[Test]
    public function test_has_correct_analyzer_metadata(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('metadata');
        $method->setAccessible(true);
        $metadata = $method->invoke($analyzer);

        $this->assertInstanceOf(AnalyzerMetadata::class, $metadata);
        $this->assertEquals('nesting-depth', $metadata->id);
        $this->assertEquals('Nesting Depth Analyzer', $metadata->name);
        $this->assertEquals(Severity::Medium, $metadata->severity);
        $this->assertStringContainsString('nested', $metadata->description);
    }

    #[Test]
    public function test_global_scope_code(): void
    {
        $code = <<<'PHP'
<?php

if ($a) {
    if ($b) {
        if ($c) {
            if ($d) {
                if ($e) {
                    // Depth 5 in global scope
                    echo 'deep';
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/global.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertEquals('global scope (file-level code)', $issues[0]->metadata['context']);
    }
}
