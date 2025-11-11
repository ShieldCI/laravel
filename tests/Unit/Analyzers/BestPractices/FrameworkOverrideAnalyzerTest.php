<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\FrameworkOverrideAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class FrameworkOverrideAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new FrameworkOverrideAnalyzer($this->parser);
    }

    public function test_passes_with_custom_classes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CustomService
{
    public function handle()
    {
        // Custom implementation
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CustomService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_framework_class_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Http\Request;

class CustomRequest extends Request
{
    public function getCustomHeader()
    {
        return $this->header('X-Custom-Header');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/CustomRequest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('framework', $result);
    }

    public function test_detects_builder_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Database;

use Illuminate\Database\Eloquent\Builder;

class CustomBuilder extends Builder
{
    public function whereActive()
    {
        return $this->where('active', true);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Database/CustomBuilder.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_passes_with_boot_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($product) {
            $product->slug = str_slug($product->name);
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Product.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_provides_macro_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Http\Response;

class CustomResponse extends Response
{
    public function withCustomHeader($value)
    {
        return $this->header('X-Custom', $value);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/CustomResponse.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('macro', $issues[0]->recommendation);
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
