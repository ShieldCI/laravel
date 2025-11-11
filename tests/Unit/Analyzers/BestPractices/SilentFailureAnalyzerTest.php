<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\SilentFailureAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class SilentFailureAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new SilentFailureAnalyzer($this->parser);
    }

    public function test_passes_with_proper_exception_handling(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

class PaymentService
{
    public function processPayment()
    {
        try {
            // Process payment
        } catch (\Exception $e) {
            Log::error('Payment failed: ' . $e->getMessage());
            throw $e;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PaymentService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_empty_catch_block(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function deleteUser($id)
    {
        try {
            // Delete user
        } catch (\Exception $e) {
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('catch', $result);
    }

    public function test_detects_catch_without_logging(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function createOrder()
    {
        try {
            // Create order
        } catch (\Exception $e) {
            return null;
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
    }

    public function test_detects_suppressed_errors(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FileService
{
    public function readFile($path)
    {
        $content = @file_get_contents($path);
        return $content;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/FileService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('suppression', $result);
    }

    public function test_passes_with_logged_exceptions(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

class ApiService
{
    public function callApi()
    {
        try {
            // API call
        } catch (\Exception $e) {
            Log::error('API call failed', ['error' => $e->getMessage()]);
            return false;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_provides_logging_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ImportService
{
    public function import()
    {
        try {
            // Import data
        } catch (\Exception $e) {
            // Do nothing
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ImportService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('log', $issues[0]->recommendation);
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
