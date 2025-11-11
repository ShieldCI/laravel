<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\GenericExceptionCatchAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class GenericExceptionCatchAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new GenericExceptionCatchAnalyzer($this->parser);
    }

    public function test_passes_with_specific_exceptions(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Database\QueryException;
use InvalidArgumentException;

class UserService
{
    public function createUser(array $data)
    {
        try {
            // Create user
        } catch (QueryException $e) {
            // Handle database error
        } catch (InvalidArgumentException $e) {
            // Handle validation error
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_generic_exception_catch(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Exception;

class PaymentService
{
    public function processPayment()
    {
        try {
            // Process payment
        } catch (Exception $e) {
            // Generic catch
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PaymentService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Exception', $result);
    }

    public function test_detects_throwable_catch(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Throwable;

class OrderService
{
    public function createOrder()
    {
        try {
            // Create order
        } catch (Throwable $e) {
            // Too generic
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Throwable', $result);
    }

    public function test_provides_specific_exception_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    public function call()
    {
        try {
            // API call
        } catch (\Exception $e) {
            // Handle
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('specific', $issues[0]->recommendation);
    }

    public function test_ignores_files_with_parse_errors(): void
    {
        $code = '<?php this is invalid PHP code {{{';

        $tempDir = $this->createTempDirectory(['Invalid.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
