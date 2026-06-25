<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Support\ModelTableResolver;
use ShieldCI\Tests\AnalyzerTestCase;

class ModelTableResolverTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        throw new \LogicException('No analyzer under test.');
    }

    private function resolver(): ModelTableResolver
    {
        return new ModelTableResolver(new AstParser);
    }

    public function test_returns_null_when_no_models_directory(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $this->assertNull($this->resolver()->tableFor($basePath, 'GitHubInstallation'));
    }

    public function test_resolves_explicit_table_override(): void
    {
        // Conventional name would be git_hub_installations; the override wins.
        $model = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class GitHubInstallation extends Model
{
    protected $table = 'github_installations';
}
PHP;

        $basePath = $this->createTempDirectory([
            'app/Models/GitHubInstallation.php' => $model,
        ]);

        $this->assertSame('github_installations', $this->resolver()->tableFor($basePath, 'GitHubInstallation'));
    }

    public function test_returns_null_for_model_without_table_override(): void
    {
        $model = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
}
PHP;

        $basePath = $this->createTempDirectory([
            'app/Models/User.php' => $model,
        ]);

        // No override declared → caller falls back to the naming convention.
        $this->assertNull($this->resolver()->tableFor($basePath, 'User'));
    }

    public function test_skips_non_php_files_in_models_directory(): void
    {
        $model = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Widget extends Model
{
    protected $table = 'widgets_custom';
}
PHP;

        $basePath = $this->createTempDirectory([
            'app/Models/Widget.php' => $model,
            'app/Models/notes.txt' => 'not php',
        ]);

        // The .txt file is skipped; the real model override still resolves.
        $this->assertSame('widgets_custom', $this->resolver()->tableFor($basePath, 'Widget'));
    }

    public function test_skips_files_with_empty_ast(): void
    {
        $basePath = $this->createTempDirectory([
            'app/Models/Empty.php' => '<?php',
        ]);

        // A file that parses to an empty AST registers no override.
        $this->assertNull($this->resolver()->tableFor($basePath, 'Empty'));
    }

    public function test_skips_anonymous_classes(): void
    {
        $model = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

return new class extends Model
{
    protected $table = 'anon';
};
PHP;

        $basePath = $this->createTempDirectory([
            'app/Models/Anon.php' => $model,
        ]);

        // An anonymous class has no name, so no override is registered under any short name.
        $this->assertNull($this->resolver()->tableFor($basePath, 'Anon'));
    }

    public function test_resolves_override_alongside_other_class_members(): void
    {
        $model = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    public const STATUS = 'open';

    public function customer()
    {
        return $this->belongsTo(Customer::class);
    }

    protected $table = 'invoices_custom';
}
PHP;

        $basePath = $this->createTempDirectory([
            'app/Models/Invoice.php' => $model,
        ]);

        // Non-property statements (const, method) are skipped before the $table property.
        $this->assertSame('invoices_custom', $this->resolver()->tableFor($basePath, 'Invoice'));
    }
}
