<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\FrameworkOverrideAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class FrameworkOverrideAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best_practices' => $config,
                ],
            ],
        ]);

        return new FrameworkOverrideAnalyzer($this->parser, $configRepo);
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

    // NEVER_EXTEND Tests (High Severity)

    public function test_detects_application_extension_with_high_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

use Illuminate\Foundation\Application;

class CustomApplication extends Application
{
    public function customMethod()
    {
        return 'custom';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['CustomApplication.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertEquals('high', $issues[0]->severity->value);
        $this->assertStringContainsString('Application', $issues[0]->message);
    }

    public function test_detects_http_kernel_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel;

class CustomKernel extends Kernel
{
    protected $middleware = [];
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/CustomKernel.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
    }

    public function test_detects_router_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Routing;

use Illuminate\Routing\Router;

class CustomRouter extends Router
{
    public function customRoute()
    {
        return $this->get('/custom', 'CustomController@index');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Routing/CustomRouter.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
        $this->assertStringContainsString('Router', $issues[0]->message);
    }

    public function test_detects_connection_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Database;

use Illuminate\Database\Connection;

class CustomConnection extends Connection
{
    public function customQuery()
    {
        return $this->select('SELECT * FROM users');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Database/CustomConnection.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
    }

    public function test_detects_query_builder_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Database;

use Illuminate\Database\Query\Builder;

class CustomQueryBuilder extends Builder
{
    public function whereCustom()
    {
        return $this->where('custom', 1);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Database/CustomQueryBuilder.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
    }

    public function test_detects_validator_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Validation;

use Illuminate\Validation\Validator;

class CustomValidator extends Validator
{
    public function customRule()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Validation/CustomValidator.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
        $this->assertStringContainsString('Validator::extend()', $issues[0]->recommendation);
    }

    // RARELY_EXTEND Tests (Medium Severity)

    public function test_detects_redirect_response_extension_with_medium_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Http\RedirectResponse;

class CustomRedirectResponse extends RedirectResponse
{
    public function withCustomData($data)
    {
        return $this->with('custom', $data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/CustomRedirectResponse.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertEquals('medium', $issues[0]->severity->value);
    }

    public function test_detects_json_response_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Http\JsonResponse;

class CustomJsonResponse extends JsonResponse
{
    public function withMeta($meta)
    {
        $data = $this->getData(true);
        $data['meta'] = $meta;
        $this->setData($data);
        return $this;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/CustomJsonResponse.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('medium', $issues[0]->severity->value);
    }

    public function test_detects_facade_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Support;

use Illuminate\Support\Facades\Facade;

class CustomFacade extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'custom';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Support/CustomFacade.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('medium', $issues[0]->severity->value);
        $this->assertStringContainsString('dependency injection', $issues[0]->recommendation);
    }

    public function test_passes_with_service_provider_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class CustomServiceProvider extends ServiceProvider
{
    public function register()
    {
        //
    }

    public function boot()
    {
        //
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Providers/CustomServiceProvider.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // ServiceProvider is designed to be extended
    }

    // OK_TO_EXTEND Tests (Should Pass)

    public function test_passes_with_model_extension(): void
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

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_command_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class CustomCommand extends Command
{
    protected $signature = 'custom:command';

    public function handle()
    {
        $this->info('Custom command');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Console/Commands/CustomCommand.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_form_request_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreUserRequest extends FormRequest
{
    public function rules()
    {
        return [
            'name' => 'required|string',
            'email' => 'required|email',
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Requests/StoreUserRequest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_controller_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Routing\Controller;

class UserController extends Controller
{
    public function index()
    {
        return view('users.index');
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

    public function test_passes_with_middleware_extension(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\TrimStrings as Middleware;

class CustomTrimStrings extends Middleware
{
    protected $except = [
        'password',
        'password_confirmation',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Middleware/CustomTrimStrings.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // Matching Logic Tests

    public function test_detects_short_class_name(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Http\Request;

class CustomRequest extends Request
{
    // Using short name
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/CustomRequest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_fully_qualified_class_name(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http;

class CustomRequest extends \Illuminate\Http\Request
{
    // Using fully qualified name
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/CustomRequest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_multiple_overrides_in_one_file(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Http\Request;
use Illuminate\Http\Response;

class CustomRequest extends Request
{
    public function getCustomHeader()
    {
        return $this->header('X-Custom');
    }
}

class CustomResponse extends Response
{
    public function withCustomHeader($value)
    {
        return $this->header('X-Custom', $value);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/Custom.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues); // Should detect both
    }

    // Path Exclusion Tests

    public function test_ignores_test_directory(): void
    {
        $code = <<<'PHP'
<?php

namespace Tests\Feature;

use Illuminate\Http\Request;

class CustomRequest extends Request
{
    // This is in a test file, should be ignored
}
PHP;

        $tempDir = $this->createTempDirectory(['tests/Feature/CustomRequest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // Should pass because test files are excluded
    }

    public function test_ignores_vendor_directory(): void
    {
        $code = <<<'PHP'
<?php

namespace Vendor\Package;

use Illuminate\Http\Request;

class CustomRequest extends Request
{
    // This is in vendor, should be ignored
}
PHP;

        $tempDir = $this->createTempDirectory(['vendor/package/CustomRequest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // Should pass because vendor is excluded
    }

    // Recommendation Tests

    public function test_provides_specific_recommendation_for_request(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Http\Request;

class CustomRequest extends Request
{
    public function getCustomHeader()
    {
        return $this->header('X-Custom');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/CustomRequest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('Request::macro()', $issues[0]->recommendation);
        $this->assertStringContainsString('FormRequest', $issues[0]->recommendation);
    }

    public function test_provides_specific_recommendation_for_builder(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Database;

// Use fully qualified name to ensure we test Eloquent\Builder specifically
class CustomBuilder extends \Illuminate\Database\Eloquent\Builder
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
        $issues = $result->getIssues();
        $this->assertStringContainsString('query scopes', $issues[0]->recommendation);
        $this->assertStringContainsString('scopeActive', $issues[0]->recommendation);
    }

    public function test_provides_specific_recommendation_for_router(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Routing;

use Illuminate\Routing\Router;

class CustomRouter extends Router
{
    public function customRoute()
    {
        return $this->get('/custom', 'CustomController@index');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Routing/CustomRouter.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('Router::macro()', $issues[0]->recommendation);
        $this->assertStringContainsString('extremely dangerous', $issues[0]->recommendation);
    }

    // Configurability Tests

    public function test_supports_custom_never_extend_list(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MyCustomBaseClass
{
    public function handle()
    {
        return 'base';
    }
}

class ExtendingClass extends MyCustomBaseClass
{
    public function handle()
    {
        return 'extended';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/Custom.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'framework-override' => [
                'never_extend' => ['MyCustomBaseClass'],
                'rarely_extend' => [],
                'ok_to_extend' => [],
            ],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('MyCustomBaseClass', $issues[0]->message);
        $this->assertEquals('high', $issues[0]->severity->value);
    }

    public function test_supports_custom_ok_to_extend_list(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Http\Request;

class CustomRequest extends Request
{
    public function getCustomHeader()
    {
        return $this->header('X-Custom');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Http/CustomRequest.php' => $code]);

        // Allow Request extension by adding to OK list
        $analyzer = $this->createAnalyzer([
            'framework-override' => [
                'never_extend' => [],
                'rarely_extend' => [],
                'ok_to_extend' => ['Illuminate\\Http\\Request'],
            ],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // Should pass because Request is now allowed
    }
}
