<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\EnvironmentCheckSmellAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class EnvironmentCheckSmellAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EnvironmentCheckSmellAnalyzer($this->parser);
    }

    public function test_passes_with_config_values(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CacheService
{
    public function getCacheTtl()
    {
        return config('cache.ttl', 3600);
    }

    public function isDebugEnabled()
    {
        return config('app.debug', false);
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

    public function test_detects_app_environment_check(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\App;

class LogService
{
    public function shouldLog()
    {
        if (App::environment('production')) {
            return true;
        }
        return false;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LogService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('environment()', $result);
    }

    public function test_detects_app_helper_environment_check(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FeatureService
{
    public function isFeatureEnabled()
    {
        if (app()->environment('production')) {
            return false;
        }
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/FeatureService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('environment()', $result);
    }

    public function test_skips_service_providers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\App;

class AppServiceProvider extends ServiceProvider
{
    public function register()
    {
        if (App::environment('local')) {
            // Register local services
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Providers/AppServiceProvider.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_exception_handler(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Support\Facades\App;

class Handler
{
    public function report($exception)
    {
        if (App::environment('production')) {
            // Send to external service
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Exceptions/Handler.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_provides_config_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\App;

class PaymentService
{
    public function process()
    {
        if (App::environment('production')) {
            // Use live API
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
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('config', $issues[0]->recommendation);
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
