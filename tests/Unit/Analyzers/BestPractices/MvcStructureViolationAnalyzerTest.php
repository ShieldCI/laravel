<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\MvcStructureViolationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MvcStructureViolationAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MvcStructureViolationAnalyzer($this->parser);
    }

    public function test_passes_with_proper_mvc_structure(): void
    {
        $modelCode = <<<'PHP'
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

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function index()
    {
        $users = User::all();
        return view('users.index', compact('users'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/User.php' => $modelCode,
            'Controllers/UserController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_view_rendering_in_model(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    public function render()
    {
        return view('products.show', ['product' => $this]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Product.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('rendering method', $result);
    }

    public function test_detects_view_helper_call_in_model(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Article extends Model
{
    public function getHtml()
    {
        return view('articles.partial', ['article' => $this])->render();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Article.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('calls view() helper', $result);
    }

    public function test_detects_large_controller_methods(): void
    {
        // Create a controller method with more than 50 lines
        $largeMethodLines = str_repeat("        \$data[] = 'line';\n", 60);

        $code = <<<PHP
<?php

namespace App\Http\Controllers;

use App\Models\Order;

class OrderController extends Controller
{
    public function processOrder(\$id)
    {
{$largeMethodLines}
        return view('orders.success');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Controllers/OrderController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('lines', $result);
    }

    public function test_detects_db_query_in_view(): void
    {
        $viewCode = <<<'BLADE'
<div>
    @php
        $users = DB::table('users')->where('active', true)->get();
    @endphp

    @foreach($users as $user)
        <p>{{ $user->name }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/users.blade.php' => $viewCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('database query', $result);
    }

    public function test_detects_model_create_in_view(): void
    {
        $viewCode = <<<'BLADE'
<div>
    @php
        User::create(['name' => 'Test']);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/test.blade.php' => $viewCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('model creation', $result);
    }

    public function test_provides_mvc_recommendations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function toHtml()
    {
        return view('posts.html', ['post' => $this]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('controller', $issues[0]->recommendation);
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
