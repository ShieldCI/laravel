<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\SilentFailureAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class SilentFailureAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        $bestPracticesConfig = [
            'enabled' => true,
            'silent-failure' => [
                'whitelist_dirs' => $config['whitelist_dirs'] ?? [
                    'tests',
                    'database/seeders',
                    'database/factories',
                ],
                'whitelist_classes' => $config['whitelist_classes'] ?? [
                    '*Test',
                    '*TestCase',
                    '*Seeder',
                    'DatabaseSeeder',
                ],
                'whitelist_exceptions' => $config['whitelist_exceptions'] ?? [
                    'ModelNotFoundException',
                    'NotFoundException',
                    'NotFoundHttpException',
                    'ValidationException',
                ],
                'whitelist_error_suppression_functions' => $config['whitelist_error_suppression_functions'] ?? [
                    'unlink',
                    'fopen',
                    'file_get_contents',
                    'mkdir',
                    'rmdir',
                ],
            ],
        ];

        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => $bestPracticesConfig,
                ],
            ],
        ]);

        return new SilentFailureAnalyzer($this->parser, $configRepo);
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
        $this->assertHasIssueContaining('Empty catch block', $result);
    }

    public function test_detects_catch_without_logging_or_rethrow(): void
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
            // Silent failure - no logging or rethrow
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
        $this->assertHasIssueContaining('does not log', $result);
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
        $content = @fgets($path);
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

    public function test_passes_with_report_helper(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class NotificationService
{
    public function sendNotification()
    {
        try {
            // Send notification
        } catch (\Exception $e) {
            report($e);
            return false;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/NotificationService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_sentry_capture_exception(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentService
{
    public function process()
    {
        try {
            // Process payment
        } catch (\Exception $e) {
            \Sentry\captureException($e);
            return false;
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

    public function test_passes_with_logger_method_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class LoggingService
{
    private $logger;

    public function doSomething()
    {
        try {
            // Do something
        } catch (\Exception $e) {
            $this->logger->error('Failed', ['exception' => $e]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LoggingService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_rethrow(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataService
{
    public function importData()
    {
        try {
            // Import data
        } catch (\Exception $e) {
            throw new ImportException('Import failed', 0, $e);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_graceful_fallback(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class AvatarService
{
    public function getAvatar($userId)
    {
        try {
            return $this->fetchAvatar($userId);
        } catch (NotFoundException $e) {
            return $this->getDefaultAvatar();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/AvatarService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_whitelisted_exception_types(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Database\Eloquent\ModelNotFoundException;

class UserService
{
    public function findUser($id)
    {
        try {
            return User::findOrFail($id);
        } catch (ModelNotFoundException $e) {
            return null;
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

    public function test_ignores_whitelisted_directories(): void
    {
        $code = <<<'PHP'
<?php

namespace Tests\Feature;

class UserTest
{
    public function test_something()
    {
        try {
            // Test code
        } catch (\Exception $e) {
            // Empty catch in test - acceptable
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['tests/Feature/UserTest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_whitelisted_classes(): void
    {
        $code = <<<'PHP'
<?php

namespace Tests\Unit;

class PaymentTest
{
    public function test_payment_processing()
    {
        try {
            // Test code
        } catch (\Exception $e) {
            // Empty catch in test - acceptable
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Unit/PaymentTest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_whitelisted_error_suppression_functions(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FileService
{
    public function deleteFile($path)
    {
        @unlink($path);
    }

    public function openFile($path)
    {
        $handle = @fopen($path, 'r');
        return $handle;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/FileService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_multiple_silent_failures_in_one_file(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MultiService
{
    public function method1()
    {
        try {
            // Do something
        } catch (\Exception $e) {
            // Silent failure 1
        }
    }

    public function method2()
    {
        try {
            // Do something else
        } catch (\Exception $e) {
            // Silent failure 2
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MultiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }

    public function test_respects_custom_whitelist_exceptions(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CustomService
{
    public function doSomething()
    {
        try {
            // Do something
        } catch (MyCustomException $e) {
            return null;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CustomService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'whitelist_exceptions' => ['MyCustomException'],
        ]);
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
        $this->assertStringContainsString('log', strtolower($issues[0]->recommendation));
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

    public function test_passes_with_logger_helper(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CacheService
{
    public function clearCache()
    {
        try {
            // Clear cache
        } catch (\Exception $e) {
            logger()->error('Cache clear failed', ['exception' => $e]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CacheService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_psr3_logger_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MonitoringService
{
    private $logger;

    public function monitor()
    {
        try {
            // Monitor
        } catch (\Exception $e) {
            $this->logger->critical('Monitoring failed', ['error' => $e]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MonitoringService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_non_whitelisted_error_suppression(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DatabaseService
{
    public function query($sql)
    {
        $result = @mysql_query($sql);
        return $result;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DatabaseService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('suppression', $result);
    }

    public function test_passes_with_assignment_in_catch_block(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConfigService
{
    public function getConfig()
    {
        try {
            $config = $this->loadFromFile();
        } catch (\Exception $e) {
            $config = $this->getDefaultConfig();
        }
        return $config;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ConfigService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_metadata_contains_correct_information(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('silent-failure', $metadata->id);
        $this->assertSame('Silent Failure Analyzer', $metadata->name);
        $this->assertStringContainsString('catch', $metadata->description);
        $this->assertStringContainsString('suppression', $metadata->description);
    }
}
