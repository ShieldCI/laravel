<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\UnguardedModelsAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class UnguardedModelsAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new UnguardedModelsAnalyzer($this->parser);
    }

    public function test_passes_with_no_unguard_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $fillable = ['name', 'email'];

    public function save(array $options = [])
    {
        return parent::save($options);
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

    public function test_detects_model_unguard(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Console\Commands;

use Illuminate\Database\Eloquent\Model;

class ImportCommand
{
    public function handle()
    {
        Model::unguard();

        // Import data...
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Commands/ImportCommand.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Model::unguard()', $result);
    }

    public function test_detects_eloquent_unguard(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Database\Eloquent\Eloquent;

class DataSeeder
{
    public function run()
    {
        Eloquent::unguard();

        // Seed data...
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['DataSeeder.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('unguard()', $result);
    }

    public function test_critical_severity_in_controllers(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Database\Eloquent\Model;

class UserController extends Controller
{
    public function store()
    {
        Model::unguard();

        User::create(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Model::unguard()', $result);

        $issues = $result->getIssues();
        $this->assertSame(Severity::Critical, $issues[0]->severity);
    }

    public function test_medium_severity_in_seeders(): void
    {
        $code = <<<'PHP'
<?php

namespace Database\Seeders;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    public function run()
    {
        Model::unguard();

        $this->call([
            UserSeeder::class,
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['database/seeders/DatabaseSeeder.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Model::unguard()', $result);

        $issues = $result->getIssues();
        $this->assertSame(Severity::Medium, $issues[0]->severity);
    }

    public function test_low_severity_in_tests(): void
    {
        $code = <<<'PHP'
<?php

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Tests\TestCase;

class UserTest extends TestCase
{
    public function test_user_creation()
    {
        Model::unguard();

        $user = User::create([
            'name' => 'Test User',
        ]);

        $this->assertNotNull($user);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['tests/Feature/UserTest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Model::unguard()', $result);

        $issues = $result->getIssues();
        $this->assertSame(Severity::Low, $issues[0]->severity);
    }

    public function test_detects_unguard_without_reguard(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Database\Eloquent\Model;

class ImportService
{
    public function import(array $data)
    {
        Model::unguard();

        foreach ($data as $item) {
            User::create($item);
        }

        // Missing Model::reguard()!
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ImportService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Model::unguard()', $result);
    }

    public function test_detects_multiple_unguard_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Database\Eloquent\Model;

class DataService
{
    public function importUsers()
    {
        Model::unguard();
        // Import users...
    }

    public function importProducts()
    {
        Model::unguard();
        // Import products...
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }

    public function test_ignores_other_unguard_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class SecurityService
{
    public function unguard()
    {
        // This is a custom unguard method, not Model::unguard()
        return true;
    }

    public function process()
    {
        $this->unguard();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/SecurityService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_recommends_force_fill_alternative(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Database\Eloquent\Model;

class UserService
{
    public function createUser(array $data)
    {
        Model::unguard();

        $user = User::create($data);

        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Check for recommendation about alternatives (forceFill or just unguard)
        $this->assertHasIssueContaining('unguard', $result);
    }

    public function test_detects_unguard_in_model_definition(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class BaseModel extends Model
{
    public function __construct(array $attributes = [])
    {
        Model::unguard();

        parent::__construct($attributes);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/BaseModel.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('unguard()', $result);
    }

    public function test_passes_with_proper_fillable_usage(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        $validated = request()->validate([
            'name' => 'required',
            'email' => 'required|email',
        ]);

        $user = User::create($validated);

        return response()->json($user);
    }

    public function update(User $user)
    {
        $validated = request()->validate([
            'name' => 'sometimes|required',
        ]);

        $user->fill($validated)->save();

        return response()->json($user);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_reguard_is_called_after_unguard(): void
    {
        $code = <<<'PHP'
<?php

use Illuminate\Database\Eloquent\Model;

class BatchImporter
{
    public function import(array $payload)
    {
        Model::unguard();

        foreach ($payload as $record) {
            User::create($record);
        }

        Model::reguard();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/BatchImporter.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_vendor_directory(): void
    {
        $code = <<<'PHP'
<?php

namespace Illuminate\Database\Eloquent;

use Illuminate\Database\Eloquent\Model;

class LegacyModel
{
    public static function boot()
    {
        Model::unguard();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['vendor/laravel/framework/src/LegacyModel.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
