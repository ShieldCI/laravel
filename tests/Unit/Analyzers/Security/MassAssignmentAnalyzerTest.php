<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\MassAssignmentAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
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

    public function test_detects_model_without_fillable_or_guarded(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    // No $fillable or $guarded
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('lacks mass assignment protection', $result);
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
        $this->assertStringContainsString('Whitelist', $exceptIssue->recommendation);
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
    // No protection
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
        $this->assertHasIssueContaining('lacks mass assignment protection', $result);
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
}
