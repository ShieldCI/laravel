<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\FatModelAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class FatModelAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new FatModelAnalyzer($this->parser);
    }

    public function test_passes_with_small_model(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $fillable = ['name', 'email'];

    public function posts()
    {
        return $this->hasMany(Post::class);
    }

    public function getFullNameAttribute()
    {
        return $this->first_name . ' ' . $this->last_name;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_model_with_too_many_business_methods(): void
    {
        // Create a model with >15 business methods (threshold is 15)
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function businessMethod{$i}()\n    {\n        return 'value';\n    }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    protected \$fillable = ['name', 'price'];
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Product.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('business methods', $result);
    }

    public function test_detects_model_with_too_many_lines(): void
    {
        // Create a model with >300 lines (threshold is 300)
        $lines = str_repeat("    // Comment line\n", 310);

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Order extends Model
{
{$lines}
    protected \$fillable = ['user_id', 'total'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Order.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('lines', $result);
    }

    public function test_provides_refactoring_recommendation(): void
    {
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function businessMethod{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Invoice.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('service', $issues[0]->recommendation);
    }

    public function test_ignores_non_model_classes(): void
    {
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Services;

class LargeService
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LargeService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
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
