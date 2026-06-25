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
}
