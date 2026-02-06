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
                'whitelist_error_suppression_static_methods' => $config['whitelist_error_suppression_static_methods'] ?? [
                    'Storage::delete',
                    'Storage::deleteDirectory',
                    'File::delete',
                    'File::deleteDirectory',
                ],
                'whitelist_error_suppression_instance_methods' => $config['whitelist_error_suppression_instance_methods'] ?? [
                    'delete',
                    'close',
                    'unlink',
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
        } catch (\RuntimeException $e) {
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
    private $silentCount = 0;

    public function createOrder()
    {
        try {
            // Create order
        } catch (\Exception $e) {
            // Silent failure - no logging or rethrow, just counting
            $this->silentCount++;
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
        } catch (\RuntimeException $e) {
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
        } catch (\RuntimeException $e) {
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
        } catch (\RuntimeException $e) {
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
        } catch (\RuntimeException $e) {
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
        } catch (\RuntimeException $e) {
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
            // Empty catch in test
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
        } catch (\RuntimeException $e) {
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
        } catch (\RuntimeException $e) {
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
        } catch (\RuntimeException $e) {
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

    public function test_passes_when_empty_catch_has_intentional_comment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FileService
{
    public function readOptionalFile($path)
    {
        try {
            return file_get_contents($path);
        } catch (\Exception $e) {
            // Intentionally ignored: file is optional and may not exist
        }
        return null;
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

    public function test_fails_when_catch_only_dispatches_event(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function processOrder($order)
    {
        try {
            $this->processPayment($order);
        } catch (\RuntimeException $e) {
            // Dispatching an event is NOT logging - the exception details are lost
            event(new OrderFailed($order));
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Event dispatching doesn't count as logging - should be flagged
        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
    }

    public function test_fails_when_catch_only_dispatches_job(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class NotificationService
{
    public function sendNotification($user)
    {
        try {
            $this->sendEmail($user);
        } catch (\RuntimeException $e) {
            // Dispatching a job is NOT logging - the exception details are lost
            dispatch(new RetryNotificationJob($user));
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/NotificationService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Job dispatching doesn't count as logging - should be flagged
        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
    }

    public function test_passes_when_catch_sends_notification(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentService
{
    public function processPayment($user, $amount)
    {
        try {
            $this->charge($amount);
        } catch (\RuntimeException $e) {
            $user->notify(new PaymentFailedNotification($e));
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

    public function test_passes_when_catch_uses_abort(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    public function fetchData($endpoint)
    {
        try {
            return $this->client->get($endpoint);
        } catch (\RuntimeException $e) {
            abort(503, 'Service unavailable');
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

    public function test_passes_when_catch_uses_db_rollback(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class TransactionService
{
    public function executeTransaction($callback)
    {
        DB::beginTransaction();
        try {
            $result = $callback();
            DB::commit();
            return $result;
        } catch (\RuntimeException $e) {
            DB::rollback();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/TransactionService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_catch_calls_custom_handler(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ImportService
{
    public function import($data)
    {
        try {
            $this->processData($data);
        } catch (\RuntimeException $e) {
            $this->handleImportError($data);
        }
    }

    private function handleImportError($data)
    {
        // Handle the error
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ImportService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_exception_variable_is_used(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ErrorService
{
    public function process()
    {
        try {
            $this->doSomething();
        } catch (\RuntimeException $e) {
            $message = $e->getMessage();
            $this->storeError($message);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ErrorService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_multiple_classes_in_file(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserServiceTest
{
    public function test_something()
    {
        try {
            // Test code - should be whitelisted
        } catch (\Exception $e) {
            // Empty catch in test class
        }
    }
}

class RegularService
{
    public function doSomething()
    {
        try {
            // Regular code
        } catch (\Exception $e) {
            // This should be flagged as silent failure
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MultiClass.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should detect the issue in RegularService but not in UserServiceTest
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_fails_when_catch_only_uses_static_event_dispatch(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Event;

class EventService
{
    public function process()
    {
        try {
            $this->doSomething();
        } catch (\RuntimeException $e) {
            // Event::dispatch is NOT logging - the exception details are lost
            Event::dispatch(new ProcessFailed());
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/EventService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Static event dispatching doesn't count as logging - should be flagged
        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
    }

    public function test_fails_when_catch_only_broadcasts(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class BroadcastService
{
    public function process()
    {
        try {
            $this->doSomething();
        } catch (\RuntimeException $e) {
            // broadcast() is NOT logging - the exception details are lost
            broadcast(new ErrorOccurred());
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/BroadcastService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Broadcasting doesn't count as logging - should be flagged
        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
    }

    public function test_passes_when_catch_calls_log_method_on_this(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class LoggingService
{
    public function process()
    {
        try {
            $this->doSomething();
        } catch (\RuntimeException $e) {
            $this->logException($e);
        }
    }

    private function logException($e)
    {
        // Log the exception
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

    public function test_passes_when_catch_uses_session_flash(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class FormController
{
    public function submit()
    {
        try {
            $this->processForm();
        } catch (\RuntimeException $e) {
            session()->flash('error', 'Something went wrong');
            return redirect()->back();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Controllers/FormController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_catch_marks_job_as_failed(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Jobs;

class ProcessOrderJob
{
    public function handle()
    {
        try {
            $this->process();
        } catch (\RuntimeException $e) {
            $this->fail($e);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Jobs/ProcessOrderJob.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_catch_uses_continue(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class BatchService
{
    public function processBatch(array $items)
    {
        foreach ($items as $item) {
            try {
                $this->processItem($item);
            } catch (\RuntimeException $e) {
                continue;
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/BatchService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_catch_uses_break(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class RetryService
{
    public function retryUntilSuccess(array $servers)
    {
        foreach ($servers as $server) {
            try {
                $this->connect($server);
            } catch (\RuntimeException $e) {
                break;
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/RetryService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_catch_uses_void_return(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CleanupService
{
    public function cleanup(): void
    {
        try {
            $this->removeTemporaryFiles();
        } catch (\RuntimeException $e) {
            return;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CleanupService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_logging_nested_in_if(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

class ConditionalLogService
{
    private bool $verbose;

    public function process()
    {
        try {
            $this->doWork();
        } catch (\RuntimeException $e) {
            if ($this->verbose) {
                Log::warning('Work failed', ['error' => $e->getMessage()]);
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ConditionalLogService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_rethrow_nested_in_if(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConditionalRethrowService
{
    private bool $strict;

    public function process()
    {
        try {
            $this->doWork();
        } catch (\RuntimeException $e) {
            if ($this->strict) {
                throw $e;
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ConditionalRethrowService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_fallback_nested_in_if(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConditionalFallbackService
{
    public function fetchData(bool $useFallback)
    {
        try {
            return $this->fetchFromApi();
        } catch (\RuntimeException $e) {
            if ($useFallback) {
                return $this->getDefault();
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ConditionalFallbackService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_empty_catch_has_swallow_comment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SwallowService
{
    public function optionalCleanup()
    {
        try {
            $this->cleanup();
        } catch (\RuntimeException $e) {
            // Swallow exception — cleanup is best-effort
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/SwallowService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_empty_catch_has_suppress_comment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SilentService
{
    public function tryOptionalAction()
    {
        try {
            $this->doOptionalAction();
        } catch (\RuntimeException $e) {
            // @suppress — this action is not critical
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/SilentService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_anonymous_class_inside_whitelisted_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentServiceTest
{
    public function test_something()
    {
        $handler = new class {
            public function handle()
            {
                try {
                    // do work
                } catch (\Exception $e) {
                }
            }
        };

        try {
            // outer try
        } catch (\Exception $e) {
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PaymentServiceTest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_flags_anonymous_class_inside_non_whitelisted_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PaymentService
{
    public function process()
    {
        $handler = new class {
            public function handle()
            {
                try {
                    // do work
                } catch (\Exception $e) {
                }
            }
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PaymentService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Empty catch block', $result);
    }

    public function test_flags_class_after_whitelisted_class_with_anonymous_inner(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderServiceTest
{
    public function test_order()
    {
        $mock = new class {
            public function execute()
            {
                try {
                    // mock work
                } catch (\Exception $e) {
                }
            }
        };

        try {
            // test code
        } catch (\Exception $e) {
        }
    }
}

class OrderService
{
    public function process()
    {
        try {
            // production code
        } catch (\Exception $e) {
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderMulti.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Only OrderService's catch should be flagged (not anything in OrderServiceTest)
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_flags_union_type_with_partial_whitelist(): void
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
        } catch (ModelNotFoundException|\RuntimeException $e) {
            // ModelNotFoundException is whitelisted, but RuntimeException is not
            // Should flag the non-whitelisted type
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('non-whitelisted type(s): RuntimeException', $result);
    }

    public function test_flags_union_type_with_partial_whitelist_regardless_of_position(): void
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
        } catch (\RuntimeException|ModelNotFoundException $e) {
            // RuntimeException is first but not whitelisted
            // ModelNotFoundException is second and whitelisted
            // Should still flag RuntimeException
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('non-whitelisted type(s): RuntimeException', $result);
    }

    public function test_flags_union_type_when_no_types_are_whitelisted(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataService
{
    public function processData($data)
    {
        try {
            $this->parse($data);
        } catch (\RuntimeException|\InvalidArgumentException $e) {
            // Neither type is whitelisted, should be flagged
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Empty catch block', $result);
    }

    public function test_skips_union_type_when_all_types_are_whitelisted(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Validation\ValidationException;

class UserService
{
    public function findOrValidate($id, $data)
    {
        try {
            $user = User::findOrFail($id);
            $this->validate($data);
            return $user;
        } catch (ModelNotFoundException|ValidationException $e) {
            // Both types are whitelisted
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

    public function test_flags_multiple_non_whitelisted_types_in_union(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Database\Eloquent\ModelNotFoundException;

class MultiService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\RuntimeException|ModelNotFoundException|\LogicException $e) {
            // ModelNotFoundException (middle type) is whitelisted
            // RuntimeException and LogicException are not whitelisted
            return null;
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
        $this->assertHasIssueContaining('non-whitelisted type(s): RuntimeException|LogicException', $result);
    }

    public function test_still_analyzes_catch_body_after_partial_whitelist_warning(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Database\Eloquent\ModelNotFoundException;

class WarningService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (ModelNotFoundException|\RuntimeException $e) {
            // Partial whitelist warning should be issued
            // But empty catch body should ALSO be flagged
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/WarningService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should have both the partial whitelist warning AND the empty catch warning
        $this->assertHasIssueContaining('non-whitelisted type(s): RuntimeException', $result);
        $this->assertHasIssueContaining('Empty catch block', $result);
    }

    // ========================================================================
    // SEMANTIC FALLBACK DETECTION TESTS
    // ========================================================================

    public function test_passes_with_cache_get_fallback(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;

class CacheService
{
    public function getData($key)
    {
        try {
            return $this->fetchFromApi($key);
        } catch (\RuntimeException $e) {
            $data = Cache::get($key, $this->getDefault());
            return $data;
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

    public function test_passes_with_fallback_variable_name(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUser($id)
    {
        try {
            return $this->fetchUser($id);
        } catch (\RuntimeException $e) {
            $default = new GuestUser();
            return $default;
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

    public function test_passes_with_null_coalescing_method_call(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConfigService
{
    public function getConfig($key)
    {
        try {
            return $this->loadFromFile($key);
        } catch (\RuntimeException $e) {
            $value = $this->cached ?? $this->computeDefault();
            return $value;
        }
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

    public function test_passes_with_new_instance_in_catch(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CollectionService
{
    public function getItems()
    {
        try {
            return $this->fetchItems();
        } catch (\RuntimeException $e) {
            $items = new EmptyCollection();
            return $items;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CollectionService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_cache_remember(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;

class DataService
{
    public function getData()
    {
        try {
            return $this->fetchFromApi();
        } catch (\RuntimeException $e) {
            $data = Cache::remember('fallback', 60, fn() => []);
            return $data;
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

    public function test_passes_with_retry_method_call(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    public function callApi()
    {
        try {
            return $this->makeRequest();
        } catch (\RuntimeException $e) {
            $result = $this->retryWithBackoff();
            return $result;
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

    public function test_fails_with_simple_scalar_assignment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ProcessService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\Exception $e) {
            $x = true;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProcessService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not log', $result);
    }

    public function test_fails_with_boolean_flag_assignment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FlagService
{
    private bool $hasError = false;

    public function process()
    {
        try {
            $this->doWork();
        } catch (\Exception $e) {
            $this->hasError = true;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/FlagService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not log', $result);
    }

    public function test_fails_with_empty_array_assignment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataService
{
    public function getData()
    {
        try {
            return $this->fetchData();
        } catch (\Exception $e) {
            $data = [];
        }
        return $data;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not log', $result);
    }

    public function test_fails_with_arbitrary_string_assignment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MessageService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\Exception $e) {
            $msg = 'error occurred';
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MessageService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not log', $result);
    }

    public function test_fails_with_counter_increment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CounterService
{
    private int $errorCount = 0;

    public function process()
    {
        try {
            $this->doWork();
        } catch (\Exception $e) {
            $count = $this->errorCount + 1;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CounterService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('does not log', $result);
    }

    public function test_passes_with_ternary_method_call_fallback(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class TernaryService
{
    public function getData($condition)
    {
        try {
            return $this->fetchData();
        } catch (\RuntimeException $e) {
            $data = $condition ? $this->primary() : $this->fallbackMethod();
            return $data;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/TernaryService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_backup_variable_name(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class BackupService
{
    public function getConfig()
    {
        try {
            return $this->loadConfig();
        } catch (\RuntimeException $e) {
            $backup = [];
            return $backup;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/BackupService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_cached_variable_name(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CachedService
{
    public function getValue()
    {
        try {
            return $this->fetchValue();
        } catch (\RuntimeException $e) {
            $cached = 'default_value';
            return $cached;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CachedService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ========================================================================
    // ERROR SUPPRESSION WHITELIST - EXTENDED CALL TYPE TESTS
    // ========================================================================

    public function test_ignores_whitelisted_namespaced_function_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FileService
{
    public function deleteFile($path)
    {
        @\unlink($path);
    }

    public function openFile($path)
    {
        $handle = @\fopen($path, 'r');
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

    public function test_ignores_whitelisted_static_method_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Storage;

class StorageService
{
    public function deleteFile($path)
    {
        @Storage::delete($path);
    }

    public function deleteDirectory($path)
    {
        @Storage::deleteDirectory($path);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/StorageService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_whitelisted_static_method_calls_with_wildcard(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Storage;

class StorageService
{
    public function deleteFile($path)
    {
        @Storage::delete($path);
    }

    public function exists($path)
    {
        return @Storage::exists($path);
    }

    public function get($path)
    {
        return @Storage::get($path);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/StorageService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'whitelist_error_suppression_static_methods' => ['Storage::*'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_whitelisted_instance_method_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ResourceService
{
    public function cleanup($file, $handle)
    {
        @$file->delete();
        @$handle->close();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ResourceService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_whitelisted_instance_method_calls_with_wildcard(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CleanupService
{
    public function cleanup($resource)
    {
        @$resource->remove();
        @$resource->removeAll();
        @$resource->removeTemporary();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CleanupService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'whitelist_error_suppression_instance_methods' => ['remove*'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_flags_dynamic_function_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DynamicService
{
    public function callFunction($func, $path)
    {
        // Dynamic function call - should always be flagged
        @$func($path);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DynamicService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('suppression', $result);
    }

    public function test_flags_dynamic_static_method_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DynamicService
{
    public function callStaticMethod($class, $path)
    {
        // Dynamic class - should always be flagged
        @$class::delete($path);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DynamicService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('suppression', $result);
    }

    public function test_flags_dynamic_instance_method_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DynamicService
{
    public function callMethod($obj, $method)
    {
        // Dynamic method - should always be flagged
        @$obj->$method();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DynamicService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('suppression', $result);
    }

    public function test_flags_non_whitelisted_static_method_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CacheService
{
    public function clearCache()
    {
        // Cache::flush is not in the whitelist
        @Cache::flush();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CacheService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('suppression', $result);
    }

    public function test_flags_non_whitelisted_instance_method_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class NetworkService
{
    public function connect($client)
    {
        // send is not in the default whitelist
        @$client->send();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/NetworkService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('suppression', $result);
    }

    public function test_ignores_whitelisted_file_facade_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\File;

class FileService
{
    public function deleteFile($path)
    {
        @File::delete($path);
    }

    public function deleteDirectory($path)
    {
        @File::deleteDirectory($path);
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

    // ========================================================================
    // BUG 1: RESCUE() HANDLING TESTS
    // ========================================================================

    public function test_fails_catch_using_rescue_without_report_parameter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class RescueService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\RuntimeException $e) {
            // rescue() without third parameter does NOT report
            rescue(fn() => $this->fallbackWork());
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/RescueService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // rescue() without report=true is treated as fallback (graceful handling)
        // So this should pass
        $this->assertPassed($result);
    }

    public function test_passes_catch_using_rescue_with_report_true(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class RescueService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\RuntimeException $e) {
            // rescue() with third parameter = true DOES report
            rescue(fn() => $this->fallbackWork(), fn() => null, true);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/RescueService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // rescue() with report=true counts as logging
        $this->assertPassed($result);
    }

    public function test_passes_catch_returning_rescue_as_fallback(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class RescueService
{
    public function getData()
    {
        try {
            return $this->fetchData();
        } catch (\RuntimeException $e) {
            // Using rescue() as a fallback mechanism
            return rescue(fn() => $this->getCachedData(), 'default');
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/RescueService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // rescue() used as return value counts as graceful fallback
        $this->assertPassed($result);
    }

    // ========================================================================
    // BUG 2: UNION EXCEPTION TYPE WITH BROAD TYPES TESTS
    // ========================================================================

    public function test_flags_union_with_throwable_even_when_other_type_whitelisted(): void
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
        } catch (ModelNotFoundException|\Throwable $e) {
            // ModelNotFoundException is whitelisted, but Throwable is too broad
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

        // Should be flagged because Throwable is too broad
        $this->assertFailed($result);
        $this->assertHasIssueContaining('overly broad', $result);
    }

    public function test_flags_union_with_exception_even_when_other_type_whitelisted(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Validation\ValidationException;

class DataService
{
    public function validate($data)
    {
        try {
            $this->validateData($data);
        } catch (ValidationException|\Exception $e) {
            // ValidationException is whitelisted, but Exception is too broad
            return false;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should be flagged because Exception is too broad
        $this->assertFailed($result);
        $this->assertHasIssueContaining('overly broad', $result);
    }

    // ========================================================================
    // BUG 3: BROAD EXCEPTION TYPE DETECTION TESTS
    // ========================================================================

    public function test_flags_catch_throwable_even_with_logging(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

class ProcessService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\Throwable $e) {
            // Logging is present, but catching Throwable is still dangerous
            Log::error('Error occurred', ['exception' => $e]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProcessService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should be flagged for catching Throwable even with logging
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Throwable', $result);
        $this->assertHasIssueContaining('overly broad', $result);
    }

    public function test_flags_catch_exception_with_high_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

class GenericService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\Exception $e) {
            // Even with logging, catching Exception is a code smell
            Log::warning('Something failed', ['error' => $e->getMessage()]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/GenericService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should be flagged for catching Exception
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Exception', $issues[0]->message);
    }

    public function test_passes_catch_throwable_with_rethrow(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

class SafeService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\Throwable $e) {
            // Catching Throwable is OK if we rethrow
            Log::error('Error occurred', ['exception' => $e]);
            throw $e;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/SafeService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because we rethrow
        $this->assertPassed($result);
    }

    // ========================================================================
    // BUG 4: COMMENT PATTERN TESTS
    // ========================================================================

    public function test_fails_with_vague_acceptable_comment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class VagueService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\RuntimeException $e) {
            // This is acceptable behavior
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/VagueService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // 'acceptable' alone is too vague - should be flagged
        $this->assertFailed($result);
    }

    public function test_fails_with_vague_expected_comment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class VagueService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\RuntimeException $e) {
            // This is expected behavior
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/VagueService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // 'expected' alone is too vague - should be flagged
        $this->assertFailed($result);
    }

    public function test_passes_with_expected_exception_comment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SpecificService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\RuntimeException $e) {
            // Expected exception when file is missing
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/SpecificService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // 'expected exception' is specific enough
        $this->assertPassed($result);
    }

    public function test_passes_with_expected_to_fail_comment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FailService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\RuntimeException $e) {
            // Expected to fail when cache is cold
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/FailService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // 'expected to fail' is specific enough
        $this->assertPassed($result);
    }

    // ========================================================================
    // BUG 5: ERROR SUPPRESSION SEVERITY TESTS
    // ========================================================================

    public function test_dynamic_function_suppression_is_high_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DynamicService
{
    public function callFunction($func, $arg)
    {
        // Dynamic function call should be high severity
        @$func($arg);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DynamicService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Dynamic', $issues[0]->message);
        $this->assertSame(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }

    public function test_suppression_inside_catch_is_high_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DoubleService
{
    public function process()
    {
        try {
            $this->doWork();
        } catch (\RuntimeException $e) {
            // Error suppression inside catch = double silencing
            @file_put_contents('/tmp/error.log', $e->getMessage());
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DoubleService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Should have issue for @ inside catch
        $suppressionIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'double silencing')) {
                $suppressionIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($suppressionIssue, 'Should have double silencing issue');
        $this->assertSame(\ShieldCI\AnalyzersCore\Enums\Severity::High, $suppressionIssue->severity);
    }

    public function test_static_suppression_is_medium_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class StaticService
{
    public function process()
    {
        // Static suppression (not whitelisted) should be medium severity
        @SomeClass::doSomething();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/StaticService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }

    public function test_dynamic_static_method_suppression_is_high_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DynamicStaticService
{
    public function callMethod($class, $arg)
    {
        // Dynamic class in static call should be high severity
        @$class::doSomething($arg);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DynamicStaticService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Dynamic', $issues[0]->message);
        $this->assertSame(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }

    public function test_dynamic_instance_method_suppression_is_high_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DynamicInstanceService
{
    public function callMethod($obj, $method)
    {
        // Dynamic method in instance call should be high severity
        @$obj->$method();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DynamicInstanceService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('Dynamic', $issues[0]->message);
        $this->assertSame(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }
}
