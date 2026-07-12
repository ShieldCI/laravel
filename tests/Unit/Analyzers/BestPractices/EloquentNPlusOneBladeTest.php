<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\EloquentNPlusOneAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Tests\AnalyzerTestCase;

class EloquentNPlusOneBladeTest extends AnalyzerTestCase
{
    private const CITY_MODEL = "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass City extends Model { public function airports(){ return \$this->hasMany(Airport::class); } }";

    private const AIRPORT_MODEL = "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Airport extends Model {}";

    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EloquentNPlusOneAnalyzer($this->parser);
    }

    /** @param array<string,string> $files */
    private function analyze(array $files): ResultInterface
    {
        $dir = $this->createTempDirectory($files);
        $analyzer = new EloquentNPlusOneAnalyzer(new AstParser);
        $analyzer->setBasePath($dir);
        $analyzer->setPaths(['app', 'resources/views']);

        return $analyzer->analyze();
    }

    /** @return list<Issue> */
    private function airportIssues(ResultInterface $result): array
    {
        return array_values(array_filter($result->getIssues(), fn (Issue $i): bool => str_contains($i->message, 'airports')));
    }

    public function test_flags_lazy_relation_when_controller_does_not_eager_load(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass City extends Model { public function airports(){ return \$this->hasMany(Airport::class); } }",
            'app/Http/Controllers/CityController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityController { public function index(){ \$cities = City::all(); return view('cities.index', compact('cities')); } }",
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $issues = $this->airportIssues($result);
        $this->assertCount(1, $issues);
        $location = $issues[0]->location;
        $this->assertNotNull($location);
        $this->assertStringEndsWith('index.blade.php', $location->file);
        $this->assertStringContainsString('CityController::index', $issues[0]->recommendation);
    }

    public function test_silent_when_controller_eager_loads(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass City extends Model { public function airports(){ return \$this->hasMany(Airport::class); } }",
            'app/Http/Controllers/CityController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityController { public function index(){ \$cities = City::with('airports')->get(); return view('cities.index', compact('cities')); } }",
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * Merge policy: two controllers render the same view. Only one eager-loads the
     * relationship the view reads — a relation eager-loaded on ANY render path must be
     * treated as loaded on all, so the finding is suppressed even though the other
     * controller does not eager-load it.
     */
    public function test_silent_when_only_one_of_two_render_sites_eager_loads(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/CityIndexController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityIndexController { public function index(){ \$cities = City::all(); return view('cities.index', compact('cities')); } }",
            'app/Http/Controllers/CityMembershipController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityMembershipController { public function membership(){ \$cities = City::with('airports')->get(); return view('cities.index', compact('cities')); } }",
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * Merge policy: a view with no resolvable render site (no controller anywhere in the
     * project calls `view('partials._row', ...)`) must be skipped entirely — `resolve()`
     * returns null and `analyzeBladeFile` bails before ever compiling or scanning it.
     */
    public function test_silent_when_partial_has_no_render_site(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'resources/views/partials/_row.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * Merge policy: when a render-bound variable's type is never inferred (built via
     * `collect()` and populated inside a `chunk()` callback, rather than a direct model
     * query assignment), the variable is dropped entirely rather than analyzed — false
     * negatives are preferred to false positives on code the scanner cannot understand.
     */
    public function test_silent_when_variable_type_is_never_inferred(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/CityChunkController.php' => <<<'PHP'
                <?php
                namespace App\Http\Controllers;
                use App\Models\City;
                class CityChunkController
                {
                    public function index()
                    {
                        $cities = collect();
                        City::with('airports')->chunk(200, function ($c) use (&$cities) {
                            foreach ($c as $x) {
                                $cities->push($x);
                            }
                        });

                        return view('cities.chunked', compact('cities'));
                    }
                }
                PHP,
            'resources/views/cities/chunked.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * A relationship accessed via an explicit method call chain ending in a query-execution
     * method (`$city->airports()->count()`, as opposed to the lazy-loading property access
     * `$city->airports->count()` in the other fixtures) is caught by a distinct branch of
     * the visitor and must be flagged the same way once the render-bound type is known.
     */
    public function test_flags_method_call_query_chain_inside_view_loop(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/MethodChainController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass MethodChainController { public function index(){ \$cities = City::all(); return view('cities.methodchain', compact('cities')); } }",
            'resources/views/cities/methodchain.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports()->count() }}\n@endforeach",
        ]);

        $issues = $this->airportIssues($result);
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('MethodChainController::index', $issues[0]->recommendation);
    }

    /**
     * Pins CURRENT behavior for a bare `view('cities.bare')` call that passes no data at
     * all: no controller ever binds a type to `$cities` for this view, so the merge policy
     * has nothing to seed and the variable is never analyzable — silent, not flagged. This
     * differs from the task brief's expectation that this case is "flagged regardless of
     * bindings" via the existing query-issue logic; see the task report for why that
     * doesn't hold today (`analyzeBladeFile()` never reads `NPlusOneVisitor::getQueryIssues()`,
     * and even the relationship-issue path requires a known type to fire).
     */
    public function test_silent_when_view_call_passes_no_data(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/BareViewController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass BareViewController { public function index(){ return view('cities.bare'); } }",
            'resources/views/cities/bare.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports()->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * A vendor-published view (e.g. from a Composer package) is always skipped, even when a
     * controller renders it with a non-eager-loaded relationship that would otherwise be
     * flagged in an application view.
     */
    public function test_vendor_view_is_skipped(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/VendorViewController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass VendorViewController { public function index(){ \$cities = City::all(); return view('vendor.pkg.x', compact('cities')); } }",
            'resources/views/vendor/pkg/x.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * Part B (nested @foreach): Blade compiles nested loops by reassigning the SAME
     * `$__currentLoopData` synthetic variable at each nesting level. The unresolved N+1
     * access here is `$city->airports` — the data source of the inner loop, accessed while
     * still inside the OUTER loop body — and it is caught before the inner loop's (buggy)
     * type inference ever comes into play. See the task report for the mistyping this
     * nested compilation causes on `$airport` itself, and why it doesn't produce a false
     * positive for this fixture.
     */
    public function test_nested_foreach_not_eager_loaded_flags_outer_relationship_access(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Models/Airport.php' => self::AIRPORT_MODEL,
            'app/Http/Controllers/NestedController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass NestedController { public function index(){ \$cities = City::all(); return view('cities.nested', compact('cities')); } }",
            'resources/views/cities/nested.blade.php' => "@foreach(\$cities as \$city)\n  @foreach(\$city->airports as \$airport)\n    {{ \$airport->name }}\n  @endforeach\n@endforeach",
        ]);

        $issues = $this->airportIssues($result);
        $this->assertCount(1, $issues);
        $location = $issues[0]->location;
        $this->assertNotNull($location);
        $this->assertSame(2, $location->line);
        $this->assertStringContainsString('NestedController::index', $issues[0]->recommendation);
    }

    /**
     * Part B (nested @foreach), the design's core promise: eager-loading the relationship
     * that seeds a nested loop must silence the finding, exactly like the single-loop case.
     */
    public function test_nested_foreach_eager_loaded_is_silent(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Models/Airport.php' => self::AIRPORT_MODEL,
            'app/Http/Controllers/NestedController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass NestedController { public function index(){ \$cities = City::with('airports')->get(); return view('cities.nested', compact('cities')); } }",
            'resources/views/cities/nested.blade.php' => "@foreach(\$cities as \$city)\n  @foreach(\$city->airports as \$airport)\n    {{ \$airport->name }}\n  @endforeach\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }
}
