<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\CodeQuality\MagicNumberAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class MagicNumberAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MagicNumberAnalyzer($this->parser);
    }

    #[Test]
    public function test_detects_magic_numbers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PricingService
{
    public function calculateDiscount($price)
    {
        if ($price > 500) {
            return $price * 0.15;
        }

        if ($price > 250) {
            return $price * 0.10;
        }

        return $price * 0.05;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/PricingService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Magic number', $result);
    }

    #[Test]
    public function test_passes_with_constants(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PricingService
{
    private const TIER1_THRESHOLD = 500;
    private const TIER1_DISCOUNT = 0.15;

    public function calculateDiscount($price)
    {
        if ($price > self::TIER1_THRESHOLD) {
            return $price * self::TIER1_DISCOUNT;
        }

        return $price;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/PricingService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_excluded_numbers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Calculator
{
    public function process($value)
    {
        // These should be ignored: 0, 1, -1, 2, 10, 100, 1000
        if ($value === 0) {
            return 0;
        }

        if ($value === 1) {
            return 1;
        }

        if ($value === -1) {
            return -1;
        }

        $result = $value * 2;
        $result = $result / 10;
        $result = $result + 100;
        $result = $result - 1000;

        return $result;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Calculator.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because all numbers are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_array_indices(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ArrayHandler
{
    public function process($data)
    {
        // Array indices should be ignored
        $first = $data[0];
        $second = $data[1];
        $specific = $data[42];
        $another = $data[99];

        return [$first, $second, $specific, $another];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ArrayHandler.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because array indices are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_increment_decrement_operations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Counter
{
    public function process($value)
    {
        // These increment/decrement patterns should be ignored
        $value += 5;
        $value -= 3;
        $value = $value + 1;
        $value = $value - 1;

        return $value;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Counter.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because increment/decrement operations are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_default_parameter_values(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    // Default parameters should be ignored
    public function paginate($perPage = 15)
    {
        return $perPage;
    }

    public function limit($max = 50)
    {
        return $max;
    }

    public function timeout($seconds = 30)
    {
        return $seconds;
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

        // Should pass because default parameters are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_ignores_constant_declarations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConfigService
{
    // Constants should be ignored
    private const MAX_RETRIES = 3;
    private const TIMEOUT = 30;
    private const RATE_LIMIT = 100;

    public const DEFAULT_PAGE_SIZE = 20;

    public function process()
    {
        return self::MAX_RETRIES;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ConfigService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because constant declarations are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_floating_point_magic_numbers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MathService
{
    public function calculate($value)
    {
        // Floating point magic numbers
        $tax = $value * 0.15;
        $shipping = $value * 0.08;
        $discount = $value * 0.25;

        return $tax + $shipping - $discount;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/MathService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Magic number', $result);
    }

    #[Test]
    public function test_detects_negative_magic_numbers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class TemperatureService
{
    public function convert($celsius)
    {
        // Negative magic numbers (excluding -1)
        if ($celsius < -273) {
            return -273;
        }

        return $celsius;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/TemperatureService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Magic number', $result);
    }

    #[Test]
    public function test_severity_is_low_for_single_occurrence(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    public function process($value)
    {
        // Single occurrence of 42
        return $value * 42;
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
    public function test_severity_is_medium_for_multiple_occurrences(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    public function process($value)
    {
        // Multiple occurrences of 42 (more than 2)
        $a = $value * 42;
        $b = $value + 42;
        $c = $value - 42;

        return [$a, $b, $c];
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
    public function test_detects_magic_numbers_in_binary_operations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Calculator
{
    public function calculate($value)
    {
        // Magic numbers in binary operations
        $result = $value + 42;
        $result = $result * 3.14;
        $result = $result / 7;

        return $result;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Calculator.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(3, count($issues));
    }

    #[Test]
    public function test_detects_magic_numbers_in_function_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    public function process()
    {
        // Magic numbers in function calls
        sleep(30);
        str_repeat('x', 50);
        substr('text', 5, 20);

        return true;
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
        $this->assertHasIssueContaining('function/method call', $result);
    }

    #[Test]
    public function test_detects_magic_numbers_in_return_statements(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    public function getTimeout()
    {
        // Magic number in return statement
        return 300;
    }

    public function getRate()
    {
        return 0.15;
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
        $this->assertHasIssueContaining('return statement', $result);
    }

    #[Test]
    public function test_detects_magic_numbers_in_ternary_expressions(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    public function process($value)
    {
        // Magic numbers in ternary
        return $value > 50 ? 75 : 25;
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
        // Should detect 50, 75, and 25
        $this->assertGreaterThanOrEqual(3, count($issues));
    }

    #[Test]
    public function test_includes_usage_count_in_metadata(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    public function process($value)
    {
        // Use 42 three times
        $a = $value * 42;
        $b = $value + 42;
        $c = $value - 42;

        return [$a, $b, $c];
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
        $this->assertArrayHasKey('usage_count', $metadata);
        $this->assertSame(3, $metadata['usage_count']);
    }

    #[Test]
    public function test_has_correct_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('magic-number', $metadata->id);
        $this->assertSame('Magic Number Analyzer', $metadata->name);
        $this->assertContains('maintainability', $metadata->tags);
    }

    #[Test]
    public function test_passes_with_no_magic_numbers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    private const THRESHOLD = 500;

    public function process($value)
    {
        // Only uses constants and excluded numbers
        if ($value > self::THRESHOLD) {
            return $value * 1;
        }

        return $value * 0;
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

        $this->assertPassed($result);
    }
}
