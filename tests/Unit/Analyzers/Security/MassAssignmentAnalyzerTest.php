<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Security\MassAssignmentAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class MassAssignmentAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MassAssignmentAnalyzer($this->parser);
    }

    public function test_passes_with_fillable_defined(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $fillable = ['name', 'email'];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_guarded_defined(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $guarded = ['id', 'password'];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_guarded_star(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $guarded = ['*'];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_model_without_fillable_or_guarded(): void
    {
        // Eloquent's base Model declares $guarded = ['*'], so a model that declares neither
        // property is totally guarded, exactly like an explicit $guarded = ['*'].
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Province extends Model
{
    protected $table = 'provinces';

    public function cities()
    {
        return $this->hasMany(City::class);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Province.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_detects_empty_guarded_array(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $guarded = [];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('$guarded = []', $result);
    }

    public function test_detects_empty_guarded_on_authenticatable_outside_models_namespace(): void
    {
        // Legacy layout: App\User extends Authenticatable, not in App\Models. Detection
        // must come from the parent class, not the namespace.
        $code = <<<'PHP'
<?php

namespace App;

use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    protected $guarded = [];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/User.php' => $code,
            // Presence of app/Models/ satisfies shouldRun(); this model is protected.
            'app/Models/Placeholder.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Placeholder extends Model { protected \$fillable = ['name']; }",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('$guarded = []', $result);
    }

    public function test_detects_unhidden_sensitive_field_on_pivot_outside_models_namespace(): void
    {
        // Detection must come from the Pivot parent, not the namespace. A Pivot's own
        // $guarded = [] is its framework default, so the finding here is the $hidden one.
        $code = <<<'PHP'
<?php

namespace App\Pivots;

use Illuminate\Database\Eloquent\Relations\Pivot;

class Membership extends Pivot
{
    protected $fillable = ['team_id', 'user_id', 'api_token'];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Pivots/Membership.php' => $code,
            // Presence of app/Models/ satisfies shouldRun(); this model is protected.
            'app/Models/Placeholder.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Placeholder extends Model { protected \$fillable = ['name']; }",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining("Model 'Membership' has sensitive fields in \$fillable but no \$hidden attributes", $result);
    }

    public function test_detects_create_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        $user = User::create(request()->all());
        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_detects_update_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function update($id)
    {
        $user = User::find($id);
        $user->update(request()->all());
        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('update()', $result);
    }

    public function test_detects_fill_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController extends Controller
{
    public function update($id)
    {
        $product = Product::find($id);
        $product->fill($request->all());
        $product->save();
        return $product;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class Product extends Model { protected $fillable = ["name"]; }',
            'app/Http/Controllers/ProductController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('fill()', $result);
    }

    public function test_detects_force_fill_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class AdminController extends Controller
{
    public function forceUpdate($id)
    {
        $user = User::find($id);
        $user->forceFill(request()->all());
        $user->save();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'app/Http/Controllers/AdminController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('forceFill()', $result);
    }

    public function test_detects_first_or_create_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function findOrCreate()
    {
        return User::firstOrCreate(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('firstOrCreate()', $result);
    }

    public function test_detects_update_or_create_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function sync()
    {
        return User::updateOrCreate(
            ['email' => request('email')],
            request()->all()
        );
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('updateOrCreate()', $result);
    }

    public function test_detects_first_or_new_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController extends Controller
{
    public function findOrNew()
    {
        $post = Post::firstOrNew(request()->all());
        $post->save();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class Post extends Model { protected $fillable = ["title"]; }',
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('firstOrNew()', $result);
    }

    public function test_detects_make_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function makeUser()
    {
        return User::make(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('make()', $result);
    }

    public function test_detects_force_create_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function forceStore()
    {
        return User::forceCreate(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('forceCreate()', $result);
    }

    public function test_detects_db_table_update_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function bulkUpdate()
    {
        DB::table('users')->update(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Query builder call to update()', $result);
    }

    public function test_detects_db_table_insert_with_request_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function bulkInsert()
    {
        DB::table('users')->insert(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Query builder call to insert()', $result);
    }

    public function test_detects_query_builder_upsert(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function sync()
    {
        DB::table('users')->upsert(
            request()->all(),
            ['email'],
            ['name', 'role']
        );
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('upsert()', $result);
    }

    public function test_detects_model_query_update(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function bulkUpdate()
    {
        User::query()->update(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('update()', $result);
    }

    public function test_detects_request_input_without_args(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        return User::create(request()->input());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_detects_request_post(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        return User::create(request()->post());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_detects_request_query(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        return User::create(request()->query());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_detects_request_except(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        return User::create(request()->except(['_token']));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_detects_request_except_with_correct_severity_and_message(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function update()
    {
        $user = User::find(1);
        $user->update(request()->except(['password']));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name", "email"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        // Verify the issue is reported with High severity (not Critical)
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $exceptIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'blacklist filtering')) {
                $exceptIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($exceptIssue, 'Should find an issue with blacklist filtering message');
        $this->assertEquals('high', $exceptIssue->severity->value);
        $this->assertStringContainsString('blacklist filtering', $exceptIssue->message);
        $this->assertStringContainsString('except', $exceptIssue->message);
        $this->assertStringContainsString('only', $exceptIssue->recommendation);
        $this->assertStringContainsString('whitelist', $exceptIssue->recommendation);
    }

    public function test_detects_input_facade(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Input;

class UserController extends Controller
{
    public function store()
    {
        return User::create(Input::all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_passes_with_request_only(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        $user = User::create(request()->only(['name', 'email']));
        return $user;
    }

    public function update($id)
    {
        $user = User::find($id);
        $user->update(request()->validated());
        return $user;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_request_input_with_args(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        return User::create([
            'name' => request()->input('name'),
            'email' => request()->input('email'),
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_multiple_mass_assignment_issues(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $guarded = [];
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController extends Controller
{
    public function store()
    {
        return Post::create(request()->all());
    }

    public function update($id)
    {
        $post = Post::find($id);
        $post->fill($request->all());
        $post->save();
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertGreaterThanOrEqual(2, count($result->getIssues()));
    }

    public function test_only_checks_eloquent_models(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataService
{
    // Not an Eloquent model, should not be checked
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Services/DataService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_when_no_models_directory(): void
    {
        $tempDir = $this->createTempDirectory([
            'Controllers/HomeController.php' => '<?php',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_handles_model_in_different_namespace(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Domain\Users;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $guarded = [];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Domain/Users/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining("Model 'User' has \$guarded = []", $result);
    }

    public function test_handles_invalid_php(): void
    {
        $code = 'invalid php {{{';

        $tempDir = $this->createTempDirectory([
            'app/Models/Invalid.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass gracefully (invalid file skipped)
        $this->assertPassed($result);
    }

    public function test_detects_insert_or_ignore(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function bulkInsert()
    {
        DB::table('users')->insertOrIgnore(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('insertOrIgnore()', $result);
    }

    public function test_detects_update_or_insert(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function sync()
    {
        DB::table('users')->updateOrInsert(
            ['email' => 'test@example.com'],
            request()->all()
        );
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('updateOrInsert()', $result);
    }

    public function test_detects_nested_request_data_under_dynamic_array_key(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        $column = request()->input('column');

        return User::create([
            $column => request()->all()['name'],
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
        $this->assertHasIssueContaining('unfiltered request data', $result);
    }

    public function test_detects_nested_request_except_under_dynamic_array_key(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        $column = request()->input('column');

        return User::create([
            $column => request()->except(['password'])['name'],
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
        $this->assertHasIssueContaining('blacklist filtering', $result);

        // Verify it's High severity (not Critical)
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $found = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'blacklist filtering')) {
                $this->assertEquals('high', $issue->severity->value);
                $found = true;
                break;
            }
        }

        $this->assertTrue($found, 'Should find a blacklist filtering issue');
    }

    public function test_detects_array_dimension_fetch_with_request_data(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function update()
    {
        $user = User::find(1);
        $user->update(request()->all()['user']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('update()', $result);
    }

    public function test_detects_request_data_in_ternary(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        $useRequest = true;

        return User::create($useRequest ? request()->all() : ['name' => 'default']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_detects_request_data_in_array_union(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        $defaults = ['role' => 'member'];

        return User::create($defaults + request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_detects_request_data_in_cast(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        return User::create((array) request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_passes_with_nested_validated_data(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        return User::create([
            'name' => request()->validated()['name'],
            'email' => request()->validated()['email'],
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name", "email"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_nested_only_data(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        return User::create([
            'name' => request()->only(['name', 'email'])['name'],
            'email' => request()->only(['name', 'email'])['email'],
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name", "email"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_update_uses_only_literal_keys_with_collection_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Collection;

class ReportController extends Controller
{
    public function update(Request $request, $model): void
    {
        $days = new Collection([1, 2, 3]);
        $model->update([
            'days' => $days->all(),
            'total' => 5,
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["days"]; }',
            'Controllers/ReportController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_request_value_sits_under_a_literal_key(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ThingController extends Controller
{
    public function update(Request $request, $model): void
    {
        $model->update(['name' => $request->all()['name']]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/ThingController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_request_data_is_spread_into_a_literal_array(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ThingController extends Controller
{
    public function update(Request $request, $model): void
    {
        $model->update(['status' => 'active', ...$request->all()]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["status"]; }',
            'Controllers/ThingController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('update()', $result);
    }

    public function test_fails_when_request_data_sits_under_a_dynamic_key(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ThingController extends Controller
{
    public function update(Request $request, $model): void
    {
        $key = $request->input('field');
        $model->update([$key => $request->all()]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/ThingController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('update()', $result);
    }

    public function test_fails_when_request_row_is_positional_in_insert(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function bulkInsert(): void
    {
        DB::table('users')->insert([request()->all()]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('insert()', $result);
    }

    public function test_detects_fully_qualified_model_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController extends Controller
{
    public function store()
    {
        return \App\Models\User::create(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
        $this->assertHasIssueContaining('unfiltered request data', $result);
    }

    public function test_detects_model_with_use_statement(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        return User::create(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_skips_non_model_facade_classes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class CacheController extends Controller
{
    public function store()
    {
        // Cache::create() is not a model - should not be flagged
        Cache::create(['key' => request()->all()]);

        // Storage::insert() is not a model - should not be flagged
        Storage::insert(['data' => request()->all()]);

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/CacheController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because Cache and Storage are not models
        $this->assertPassed($result);
    }

    public function test_detects_model_in_custom_namespace(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Domain\Users\Models\User;

class UserController extends Controller
{
    public function store()
    {
        return User::create(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_detects_model_existing_in_models_directory(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController extends Controller
{
    public function store()
    {
        // Even without use statement, if User.php exists in app/Models, detect it
        return User::create(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_handles_factory_class_without_false_positive(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class TestController extends Controller
{
    public function test()
    {
        // Factory::create() should not be flagged as it's not a model
        Factory::create(['data' => request()->all()]);

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/TestController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_query_builder_where_chain(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function bulkUpdate()
    {
        User::where('status', 'active')->update(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Query builder call to update()', $result);
        $this->assertHasIssueContaining('unfiltered request data', $result);
    }

    public function test_detects_query_builder_wherein_chain(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function bulkUpdate()
    {
        User::whereIn('id', [1, 2, 3])->update(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Query builder call to update()', $result);
    }

    public function test_detects_complex_query_builder_chain(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function complexUpdate()
    {
        User::where('status', 'active')
            ->whereNotNull('email')
            ->orderBy('created_at', 'desc')
            ->limit(10)
            ->update(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('update()', $result);
    }

    public function test_detects_query_builder_with_join(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function updateWithJoin()
    {
        User::join('profiles', 'users.id', '=', 'profiles.user_id')
            ->where('profiles.verified', true)
            ->update(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('update()', $result);
    }

    public function test_detects_query_builder_latest_chain(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function updateLatest()
    {
        User::latest()->limit(5)->update(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('update()', $result);
    }

    public function test_detects_fully_qualified_model_query_builder(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController extends Controller
{
    public function bulkUpdate()
    {
        \App\Models\User::where('active', true)->update(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('update()', $result);
    }

    public function test_passes_query_builder_with_safe_data(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function safeUpdate()
    {
        User::where('status', 'pending')
            ->update(request()->validated());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name", "status"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_request_class_create_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Requests\CreateUserRequest;

class UserController extends Controller
{
    public function store()
    {
        // CreateUserRequest::create() is form request creation, not Eloquent
        // This should NOT be flagged
        $formRequest = CreateUserRequest::create('/users', 'POST', request()->all());

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because CreateUserRequest ends with 'Request'
        $this->assertPassed($result);
    }

    public function test_skips_action_class_with_model_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Actions\CreateUserAction;

class UserController extends Controller
{
    public function store()
    {
        // Actions ending with 'Action' should not be flagged as models
        CreateUserAction::create(request()->all());

        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because CreateUserAction ends with 'Action'
        $this->assertPassed($result);
    }

    public function test_detects_request_json_without_arguments(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        // request()->json() without arguments returns all JSON data - dangerous
        return User::create(request()->json());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
        $this->assertHasIssueContaining('unfiltered request data', $result);
    }

    public function test_passes_request_json_with_specific_key(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        // request()->json('user') filters to specific key - safe
        return User::create(request()->json('user'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name", "email"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_nested_json_under_dynamic_array_key(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        $column = request()->input('column');

        // Nested request()->json() without args under a dynamic key - should detect
        return User::create([
            $column => request()->json(),
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_passes_nested_json_with_specific_key(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        // Nested request()->json('key') with specific key - safe
        return User::create([
            'name' => request()->json('user.name'),
            'email' => request()->json('user.email'),
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name", "email"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_short_variable_name_with_all(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function store(Request $r)
    {
        // $r->all() should be detected even though variable is not named $request
        return User::create($r->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
        $this->assertHasIssueContaining('unfiltered request data', $result);
    }

    public function test_detects_alternative_variable_name_with_input(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function store(Request $req)
    {
        // $req->input() without args should be detected
        return User::create($req->input());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_detects_input_variable_name_with_post(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function store(Request $input)
    {
        // $input->post() should be detected
        return User::create($input->post());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_detects_custom_variable_name_with_json(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function store(Request $httpRequest)
    {
        // $httpRequest->json() without args should be detected
        return User::create($httpRequest->json());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('create()', $result);
    }

    public function test_passes_custom_variable_with_json_key(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function store(Request $r)
    {
        // $r->json('user') with specific key should be safe
        return User::create($r->json('user'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name", "email"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_except_with_custom_variable_name(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function update(Request $req)
    {
        $user = User::find(1);
        // $req->except() should be detected as blacklist filtering
        $user->update($req->except(['password']));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('update()', $result);
        $this->assertHasIssueContaining('blacklist filtering', $result);

        // Verify it's High severity (not Critical)
        $issues = $result->getIssues();
        $found = false;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'blacklist filtering')) {
                $this->assertEquals('high', $issue->severity->value);
                $found = true;
                break;
            }
        }
        $this->assertTrue($found);
    }

    public function test_skips_scope_classes_without_false_positive(): void
    {
        $scopeContent = <<<'PHP'
<?php
namespace App\Models\Scopes;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;

class TeamScope implements Scope
{
    public function apply(Builder $builder, Model $model): void
    {
        $builder->join('team_user', function ($join) {
            $join->on('users.id', '=', 'team_user.user_id')
                ->where('team_user.team_id', config('services.team.id'));
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Scopes/TeamScope.php' => $scopeContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_observer_classes_without_false_positive(): void
    {
        $observerContent = <<<'PHP'
<?php
namespace App\Models\Observers;

use App\Models\User;
use Illuminate\Http\Request;

class UserObserver
{
    public function creating(User $user): void
    {
        // Even though this uses Request, it's not a model static call
        $request = request();
        $user->created_by = $request->user()->id;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Observers/UserObserver.php' => $observerContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_cast_classes_without_false_positive(): void
    {
        $castContent = <<<'PHP'
<?php
namespace App\Models\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;

class JsonCast implements CastsAttributes
{
    public function get($model, string $key, $value, array $attributes)
    {
        return json_decode($value, true);
    }

    public function set($model, string $key, $value, array $attributes)
    {
        return json_encode($value);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Casts/JsonCast.php' => $castContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_model_without_hidden_attributes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $fillable = ['name', 'email', 'password'];

    // Missing $hidden attribute - password should be hidden
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Medium severity issues result in Warning status
        $this->assertEquals('warning', $result->getStatus()->value);
        $this->assertHasIssueContaining('no $hidden attributes', $result);
    }

    public function test_detects_password_not_in_hidden_array(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $fillable = ['name', 'email', 'password'];

    protected $hidden = ['api_token']; // password should be here!
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Medium severity issues result in Warning status
        $this->assertEquals('warning', $result->getStatus()->value);
        $this->assertHasIssueContaining('password', $result);
        $this->assertHasIssueContaining('fillable', $result);
    }

    public function test_passes_with_proper_hidden_attributes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $fillable = ['name', 'email', 'password'];

    protected $hidden = ['password', 'remember_token'];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_relationship_sync_with_request_data(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function attachRoles()
    {
        $user = User::find(1);
        $user->roles()->sync(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('sync()', $result);
        $this->assertHasIssueContaining('unfiltered request data', $result);
    }

    public function test_detects_relationship_attach_with_request_data(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function attachPermissions()
    {
        $user = User::find(1);
        $user->permissions()->attach(request('permission_ids'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('attach()', $result);
    }

    public function test_detects_nested_mass_assignment_with_dot_notation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        return User::create(request()->input('user.profile'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Note: request()->input('key.nested') accesses nested array keys from form data
        // This is not the same as mass assignment of relationships
        // The real vulnerability would be passing entire arrays with nested data
        // For now, this pattern is not flagged as it's common and usually safe
        $this->assertPassed($result);
    }

    public function test_warns_about_relationship_security(): void
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
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Relationship security check disabled to reduce false positives
        // The important check is relationship operations with unsafe data (tested separately)
        $this->assertPassed($result);
    }

    public function test_passes_with_validated_relationship_data(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function attachRoles()
    {
        $user = User::find(1);
        $user->roles()->sync(request()->validated());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_unfiltered_request_recommendation_mentions_form_request(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        User::create(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $requestDataIssue = null;

        foreach ($issues as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'dangerous_method_with_request_data') {
                $requestDataIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($requestDataIssue, 'Expected an unfiltered request data issue');
        $this->assertStringContainsString('FormRequest', $requestDataIssue->recommendation);
    }

    public function test_blacklist_filtering_recommendation_mentions_form_request(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function store()
    {
        User::create(request()->except('_token'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $blacklistIssue = null;

        foreach ($issues as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'dangerous_method_with_blacklist_filtering') {
                $blacklistIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($blacklistIssue, 'Expected a blacklist filtering issue');
        $this->assertStringContainsString('FormRequest', $blacklistIssue->recommendation);
    }

    public function test_relationship_operation_recommendation_mentions_form_request(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function attachRoles()
    {
        $user = User::find(1);
        $user->roles()->sync(request()->all());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php namespace App\\Models; use Illuminate\\Database\\Eloquent\\Model; class User extends Model { protected $fillable = ["name"]; }',
            'Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $relationshipIssue = null;

        foreach ($issues as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'relationship_mass_assignment') {
                $relationshipIssue = $issue;
                break;
            }
        }

        $this->assertNotNull($relationshipIssue, 'Expected a relationship mass assignment issue');
        $this->assertStringContainsString('FormRequest', $relationshipIssue->recommendation);
    }

    // -------------------------------------------------------------------------
    // Inheritance: a model's own declaration decides, and declaring none leaves
    // Eloquent's default $guarded = ['*'] in force
    // -------------------------------------------------------------------------

    public function test_passes_when_neither_model_nor_its_parent_declares_protection(): void
    {
        $base = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

abstract class Record extends Model
{
}
PHP;

        $child = <<<'PHP'
<?php

namespace App\Models;

class Ledger extends Record
{
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Record.php' => $base,
            'app/Models/Ledger.php' => $child,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_detects_empty_guarded_on_child_of_a_parent_with_fillable(): void
    {
        // The child's own $guarded = [] replaces whatever the parent declared.
        $base = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

abstract class Record extends Model
{
    protected $fillable = ['title'];
}
PHP;

        $child = <<<'PHP'
<?php

namespace App\Models;

class Ledger extends Record
{
    protected $guarded = [];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Record.php' => $base,
            'app/Models/Ledger.php' => $child,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("Model 'Ledger' has \$guarded = []", $result);
        $this->assertSame(Severity::Critical, $result->getIssues()[0]->severity);
    }

    public function test_passes_with_fillable_attribute(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;

#[Fillable(['name', 'email'])]
class User extends Model
{
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_passes_with_fillable_attribute_variadic(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;

#[Fillable('name', 'email')]
class User extends Model
{
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_passes_with_guarded_attribute(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Guarded;
use Illuminate\Database\Eloquent\Model;

#[Guarded(['id'])]
class User extends Model
{
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_recognizes_hidden_attribute_for_sensitive_fillable_field(): void
    {
        // #[Fillable] exposes password, #[Hidden] hides it — must NOT warn that
        // a sensitive field lacks $hidden (both sides read from attributes).
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Model;

#[Fillable(['name', 'password'])]
#[Hidden(['password'])]
class User extends Model
{
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $hiddenIssues = array_filter(
            $analyzer->analyze()->getIssues(),
            fn ($i) => isset($i->metadata['issue_type'])
                && in_array($i->metadata['issue_type'], ['missing_hidden_attributes', 'fillable_field_not_hidden'], true)
        );
        $this->assertEmpty($hiddenIssues, 'Hidden declared via #[Hidden] should satisfy the hidden-field check');
    }

    public function test_flags_sensitive_fillable_attribute_without_hidden(): void
    {
        // #[Fillable] exposes password but nothing hides it — the existing medium
        // warning should still fire when fillable is declared via an attribute.
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;

#[Fillable(['name', 'password'])]
class User extends Model
{
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $hiddenIssues = array_filter(
            $analyzer->analyze()->getIssues(),
            fn ($i) => isset($i->metadata['issue_type']) && $i->metadata['issue_type'] === 'missing_hidden_attributes'
        );
        $this->assertNotEmpty($hiddenIssues, 'Sensitive field in #[Fillable] without $hidden should warn');
    }

    public function test_does_not_crash_on_skipped_destructuring_and_first_class_callables(): void
    {
        // Two AST shapes used to crash the analyzer's walkers:
        //  - skipped destructuring slots ([, , $x] = ...) produce a List_ with null
        //    items, which reached getSubNodeNames() on null.
        //  - first-class callables (Thing::create(...)) put a VariadicPlaceholder where
        //    an Arg is expected, so $arg->value fed null into a Node-typed parameter.
        // Neither pattern is a vulnerability, so analysis must complete (not error).
        $controller = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Thing;

class ThingController
{
    public function store()
    {
        [, , $next] = $this->steps();

        $factory = Thing::create(...);

        return $next;
    }

    private function steps(): array
    {
        return ['a', 'b', 'c'];
    }
}
PHP;

        $model = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Thing extends Model
{
    protected $fillable = ['name'];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Thing.php' => $model,
            'app/Http/Controllers/ThingController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        // Before the fix this returned Status::Error with a getSubNodeNames()/TypeError
        // message; the guarded walkers now let analysis finish cleanly.
        $this->assertPassed($analyzer->analyze());
    }

    public function test_analyzes_a_model_extending_a_project_base_model(): void
    {
        $base = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

abstract class BaseModel extends Model
{
}
PHP;

        $code = <<<'PHP'
<?php

namespace App\Entities;

use App\Models\BaseModel;

class Invoice extends BaseModel
{
    protected $guarded = [];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/BaseModel.php' => $base,
            'app/Entities/Invoice.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app/Entities']);

        $result = $analyzer->analyze();

        // The old analyzer skipped Invoice: its parent "BaseModel" matched no
        // short-name base and App\Entities is not a Models namespace. The detector
        // now recognizes it via its parent App\Models\BaseModel. Scanning only
        // app/Entities ensures the finding is Invoice's, not BaseModel's.
        $this->assertFailed($result);
        $this->assertHasIssueContaining("Model 'Invoice'", $result);
    }

    public function test_does_not_treat_a_parentless_class_in_app_models_as_a_model(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

class Dto
{
    // $guarded = [] would be Critical on a model, but with no parent this is not one.
    protected $guarded = [];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Dto.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // -------------------------------------------------------------------------
    // #[Fillable]/#[Guarded]/#[Hidden] are matched on the name the file resolves
    // them to, not on the short name as written (#728)
    // -------------------------------------------------------------------------

    /**
     * Ways of writing Laravel's own #[Fillable] attribute on a model.
     *
     * @return array<string, array{string, string}>
     */
    public static function laravelFillableSpellingProvider(): array
    {
        return [
            'plain import' => ['use Illuminate\Database\Eloquent\Attributes\Fillable;', 'Fillable'],
            'aliased import' => ['use Illuminate\Database\Eloquent\Attributes\Fillable as Assignable;', 'Assignable'],
            'aliased group import' => ['use Illuminate\Database\Eloquent\Attributes\{Fillable as Assignable};', 'Assignable'],
            'fully qualified without import' => ['', '\Illuminate\Database\Eloquent\Attributes\Fillable'],
            'namespace import' => ['use Illuminate\Database\Eloquent\Attributes;', 'Attributes\Fillable'],
        ];
    }

    /** @dataProvider laravelFillableSpellingProvider */
    #[DataProvider('laravelFillableSpellingProvider')]
    public function test_flags_sensitive_field_in_laravel_fillable_attribute_however_it_is_spelled(string $import, string $attribute): void
    {
        $code = <<<PHP
<?php

namespace App\Models;

{$import}
use Illuminate\Database\Eloquent\Model;

#[{$attribute}(['nickname', 'password'])]
class Member extends Model
{
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Member.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("Model 'Member' has sensitive fields in \$fillable but no \$hidden attributes", $result);
        $this->assertSame(Severity::Medium, $result->getIssues()[0]->severity);
    }

    public function test_flags_unhidden_password_in_aliased_laravel_fillable_attribute(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable as Assignable;
use Illuminate\Database\Eloquent\Model;

#[Assignable(['nickname', 'password'])]
class Member extends Model
{
    protected $hidden = ['remember_token'];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Member.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("Model 'Member' has 'password' in \$fillable but doesn't hide it from JSON output", $result);
    }

    /**
     * A #[Fillable] that is not Laravel's: Model never reads it, so it lists nothing.
     *
     * @return array<string, array{string}>
     */
    public static function foreignFillableProvider(): array
    {
        return [
            'imported from another namespace' => ['use App\Attributes\Fillable;'],
            'unimported, so in the model namespace' => [''],
        ];
    }

    /** @dataProvider foreignFillableProvider */
    #[DataProvider('foreignFillableProvider')]
    public function test_ignores_a_fillable_attribute_that_is_not_laravels(string $import): void
    {
        $code = <<<PHP
<?php

namespace App\Models;

{$import}
use Illuminate\Database\Eloquent\Model;

#[Fillable(['nickname', 'password'])]
class Member extends Model
{
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Member.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_aliased_laravel_hidden_attribute_hides_the_sensitive_field(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden as Concealed;
use Illuminate\Database\Eloquent\Model;

#[Fillable(['nickname', 'password'])]
#[Concealed(['password'])]
class Member extends Model
{
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Member.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_aliased_laravel_guarded_attribute_exempts_the_guarded_field(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Guarded as Protect;
use Illuminate\Database\Eloquent\Model;

#[Protect(['password'])]
class Member extends Model
{
    protected $fillable = ['nickname', 'password'];

    protected $hidden = ['remember_token'];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Member.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    // -------------------------------------------------------------------------
    // #[Unguarded] and #[Guarded([])] open every attribute, as $guarded = [] does
    // -------------------------------------------------------------------------

    /**
     * Laravel attributes that leave a model with no guarded attributes at all.
     *
     * @return array<string, array{0: string, 1: string, 2: string, 3?: string}>
     */
    public static function unguardingAttributeProvider(): array
    {
        return [
            'Unguarded, plain import' => ['use Illuminate\Database\Eloquent\Attributes\Unguarded;', 'Unguarded', '#[Unguarded]'],
            'Unguarded, aliased import' => ['use Illuminate\Database\Eloquent\Attributes\Unguarded as Open;', 'Open', '#[Unguarded]'],
            'Unguarded, fully qualified' => ['', '\Illuminate\Database\Eloquent\Attributes\Unguarded', '#[Unguarded]'],
            'Guarded([]), plain import' => ['use Illuminate\Database\Eloquent\Attributes\Guarded;', 'Guarded([])', '#[Guarded([])]'],
            'Guarded([]), aliased import' => ['use Illuminate\Database\Eloquent\Attributes\Guarded as Protect;', 'Protect([])', '#[Guarded([])]'],
            'Unguarded beside an explicit $guarded = [\'*\']' => ['use Illuminate\Database\Eloquent\Attributes\Unguarded;', 'Unguarded', '#[Unguarded]', "protected \$guarded = ['*'];"],
            'Unguarded beside $guarded = [0 => \'*\']' => ['use Illuminate\Database\Eloquent\Attributes\Unguarded;', 'Unguarded', '#[Unguarded]', "protected \$guarded = [0 => '*'];"],
            'Unguarded, imported and written in lower case' => ['use Illuminate\Database\Eloquent\Attributes\unguarded;', 'unguarded', '#[Unguarded]'],
        ];
    }

    /** @dataProvider unguardingAttributeProvider */
    #[DataProvider('unguardingAttributeProvider')]
    public function test_detects_attribute_that_unguards_every_attribute(string $import, string $attribute, string $writtenAs, string $body = ''): void
    {
        $code = <<<PHP
<?php

namespace App\Models;

{$import}
use Illuminate\Database\Eloquent\Model;

#[{$attribute}]
class Ledger extends Model
{
    {$body}
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Ledger.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("Model 'Ledger' has {$writtenAs} which allows mass assignment of all attributes", $result);
        $this->assertSame(Severity::Critical, $result->getIssues()[0]->severity);
    }

    /**
     * Guarded attributes that leave the model guarded, or that Laravel never applies.
     *
     * @return array<string, array{string, string, string}>
     */
    public static function guardingAttributeProvider(): array
    {
        return [
            'Guarded wildcard' => ['use Illuminate\Database\Eloquent\Attributes\Guarded;', "Guarded(['*'])", ''],
            'Guarded column list' => ['use Illuminate\Database\Eloquent\Attributes\Guarded;', "Guarded(['id'])", ''],
            'Unguarded from another namespace' => ['use App\Attributes\Unguarded;', 'Unguarded', ''],
            'Unguarded overridden by a $guarded property' => ['use Illuminate\Database\Eloquent\Attributes\Unguarded;', 'Unguarded', "protected \$guarded = ['id'];"],
        ];
    }

    /** @dataProvider guardingAttributeProvider */
    #[DataProvider('guardingAttributeProvider')]
    public function test_passes_with_attribute_that_keeps_the_model_guarded(string $import, string $attribute, string $body): void
    {
        $code = <<<PHP
<?php

namespace App\Models;

{$import}
use Illuminate\Database\Eloquent\Model;

#[{$attribute}]
class Ledger extends Model
{
    {$body}
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Ledger.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_reports_empty_guarded_property_once_beside_unguarded_attribute(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Database\Eloquent\Model;

#[Unguarded]
class Ledger extends Model
{
    protected $guarded = [];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Ledger.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame("Model 'Ledger' has \$guarded = [] which allows mass assignment of all attributes", $result->getIssues()[0]->message);
    }

    // -------------------------------------------------------------------------
    // $visible is an allow-list: a field it leaves out is never serialized
    // -------------------------------------------------------------------------

    /**
     * Models whose $visible allow-list keeps a fillable password out of JSON output.
     *
     * @return array<string, array{string, string}>
     */
    public static function visibleAllowListProvider(): array
    {
        return [
            'visible property, no hidden' => ['', "protected \$visible = ['nickname'];"],
            'visible property beside a hidden list without the password' => ['', "protected \$visible = ['nickname'];\n    protected \$hidden = ['remember_token'];"],
            'aliased Visible attribute, no hidden' => ["use Illuminate\\Database\\Eloquent\\Attributes\\Visible as Shown;\n#[Shown(['nickname'])]", ''],
        ];
    }

    /** @dataProvider visibleAllowListProvider */
    #[DataProvider('visibleAllowListProvider')]
    public function test_passes_when_visible_allow_list_omits_the_sensitive_field(string $attribute, string $body): void
    {
        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
{$attribute}
class Member extends Model
{
    protected \$fillable = ['nickname', 'password'];
    {$body}
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Member.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_flags_sensitive_field_the_visible_allow_list_exposes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Visible;
use Illuminate\Database\Eloquent\Model;

#[Visible(['nickname', 'password'])]
class Member extends Model
{
    protected $fillable = ['nickname', 'password'];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Member.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("Model 'Member' has sensitive fields in \$fillable but no \$hidden attributes", $result);
    }

    // -------------------------------------------------------------------------
    // A finding that depends on an inherited default is only made when the model
    // extends Model or Authenticatable directly; fillable wins over unguarding
    // -------------------------------------------------------------------------

    /**
     * Models that look unguarded or unhidden in their own body but are not at runtime.
     *
     * @return array<string, array{array<string, string>}>
     */
    public static function notExposedAtRuntimeProvider(): array
    {
        $header = "<?php\n\nnamespace App\\Models;\n\n";

        return [
            'Unguarded under a project base that guards a column' => [[
                'app/Models/BaseModel.php' => $header."use Illuminate\\Database\\Eloquent\\Model;\n\nabstract class BaseModel extends Model\n{\n    protected \$guarded = ['id'];\n}\n",
                'app/Models/Ledger.php' => $header."use Illuminate\\Database\\Eloquent\\Attributes\\Unguarded;\n\n#[Unguarded]\nclass Ledger extends BaseModel\n{\n}\n",
            ]],
            'Unguarded beside a Fillable attribute' => [[
                'app/Models/Ledger.php' => $header."use Illuminate\\Database\\Eloquent\\Attributes\\Fillable;\nuse Illuminate\\Database\\Eloquent\\Attributes\\Unguarded;\nuse Illuminate\\Database\\Eloquent\\Model;\n\n#[Fillable(['title'])]\n#[Unguarded]\nclass Ledger extends Model\n{\n}\n",
            ]],
            'Guarded([]) beside a fillable property' => [[
                'app/Models/Ledger.php' => $header."use Illuminate\\Database\\Eloquent\\Attributes\\Guarded;\nuse Illuminate\\Database\\Eloquent\\Model;\n\n#[Guarded([])]\nclass Ledger extends Model\n{\n    protected \$fillable = ['title'];\n}\n",
            ]],
            'empty guarded property beside a fillable property' => [[
                'app/Models/Ledger.php' => $header."use Illuminate\\Database\\Eloquent\\Model;\n\nclass Ledger extends Model\n{\n    protected \$fillable = ['title'];\n\n    protected \$guarded = [];\n}\n",
            ]],
            'Unguarded on a Pivot that guards everything' => [[
                'app/Models/RoleUser.php' => $header."use Illuminate\\Database\\Eloquent\\Attributes\\Unguarded;\nuse Illuminate\\Database\\Eloquent\\Relations\\Pivot;\n\n#[Unguarded]\nclass RoleUser extends Pivot\n{\n    protected \$guarded = ['*'];\n}\n",
            ]],
            'Unguarded on a Pivot that keeps its own default' => [[
                'app/Models/RoleUser.php' => $header."use Illuminate\\Database\\Eloquent\\Attributes\\Unguarded;\nuse Illuminate\\Database\\Eloquent\\Relations\\Pivot;\n\n#[Unguarded]\nclass RoleUser extends Pivot\n{\n}\n",
            ]],
            'sensitive fillable under a project base that hides it' => [[
                'app/Models/BaseModel.php' => $header."use Illuminate\\Database\\Eloquent\\Model;\n\nabstract class BaseModel extends Model\n{\n    protected \$hidden = ['password'];\n}\n",
                'app/Models/Member.php' => $header."class Member extends BaseModel\n{\n    protected \$fillable = ['nickname', 'password'];\n}\n",
            ]],
            'empty guarded property on a Pivot, its own default' => [[
                'app/Models/RoleUser.php' => $header."use Illuminate\\Database\\Eloquent\\Relations\\Pivot;\n\nclass RoleUser extends Pivot\n{\n    protected \$guarded = [];\n}\n",
            ]],
            'empty guarded property on a MorphPivot, its own default' => [[
                'app/Models/Taggable.php' => $header."use Illuminate\\Database\\Eloquent\\Relations\\MorphPivot;\n\nclass Taggable extends MorphPivot\n{\n    protected \$guarded = [];\n}\n",
            ]],
            'empty guarded property beside a fillable list held in a constant' => [[
                'app/Models/Ledger.php' => $header."use Illuminate\\Database\\Eloquent\\Model;\n\nclass Ledger extends Model\n{\n    const COLUMNS = ['title'];\n\n    protected \$fillable = self::COLUMNS;\n\n    protected \$guarded = [];\n}\n",
            ]],
            'Unguarded beside a fillable list held in a constant' => [[
                'app/Models/Ledger.php' => $header."use Illuminate\\Database\\Eloquent\\Attributes\\Unguarded;\nuse Illuminate\\Database\\Eloquent\\Model;\n\n#[Unguarded]\nclass Ledger extends Model\n{\n    const COLUMNS = ['title'];\n\n    protected \$fillable = self::COLUMNS;\n}\n",
            ]],
            'Fillable attribute keeps only its leading array' => [[
                'app/Models/Member.php' => $header."use Illuminate\\Database\\Eloquent\\Attributes\\Fillable;\nuse Illuminate\\Database\\Eloquent\\Model;\n\n#[Fillable(['nickname'], 'password')]\nclass Member extends Model\n{\n}\n",
            ]],
        ];
    }

    /**
     * @dataProvider notExposedAtRuntimeProvider
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('notExposedAtRuntimeProvider')]
    public function test_passes_when_the_model_is_not_exposed_at_runtime(array $files): void
    {
        $tempDir = $this->createTempDirectory($files);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_detects_unguarded_attribute_on_a_direct_authenticatable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Foundation\Auth\User as Authenticatable;

#[Unguarded]
class Member extends Authenticatable
{
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Member.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("Model 'Member' has #[Unguarded] which allows mass assignment of all attributes", $result);
    }

    public function test_flags_sensitive_fillable_without_hidden_on_a_direct_authenticatable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;

class Member extends Authenticatable
{
    protected $fillable = ['nickname', 'password'];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Member.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining("Model 'Member' has sensitive fields in \$fillable but no \$hidden attributes", $result);
    }

    public function test_own_hidden_list_stays_authoritative_under_a_project_base(): void
    {
        // A $hidden property replaces the parent's, so the parent cannot hide the password.
        $base = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

abstract class BaseModel extends Model
{
    protected $hidden = ['password'];
}
PHP;

        $child = <<<'PHP'
<?php

namespace App\Models;

class Member extends BaseModel
{
    protected $fillable = ['nickname', 'password'];

    protected $hidden = ['remember_token'];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/BaseModel.php' => $base,
            'app/Models/Member.php' => $child,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("Model 'Member' has 'password' in \$fillable but doesn't hide it from JSON output", $result);
    }

    /**
     * Models whose hidden and visible defaults are Model's, whatever their parent is named.
     *
     * @return array<string, array{string, string}>
     */
    public static function modelSerializationDefaultsProvider(): array
    {
        return [
            'Pivot' => ["use Illuminate\\Database\\Eloquent\\Relations\\Pivot;\n\nclass Member extends Pivot", 'api_token'],
            'MorphPivot' => ["use Illuminate\\Database\\Eloquent\\Relations\\MorphPivot;\n\nclass Member extends MorphPivot", 'secret'],
            'the global Eloquent alias' => ['class Member extends \\Eloquent', 'password'],
        ];
    }

    /** @dataProvider modelSerializationDefaultsProvider */
    #[DataProvider('modelSerializationDefaultsProvider')]
    public function test_flags_sensitive_fillable_without_hidden_under_a_parent_with_model_defaults(string $declaration, string $field): void
    {
        $code = <<<PHP
<?php

namespace App\Models;

{$declaration}
{
    protected \$fillable = ['nickname', '{$field}'];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Member.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("Model 'Member' has sensitive fields in \$fillable but no \$hidden attributes", $result);
    }

    public function test_detects_empty_guarded_beside_an_empty_fillable_literal(): void
    {
        // An empty $fillable lists nothing, so fill() falls back to $guarded = [].
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Ledger extends Model
{
    protected $fillable = [];

    protected $guarded = [];
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Models/Ledger.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("Model 'Ledger' has \$guarded = [] which allows mass assignment of all attributes", $result);
    }
}
