<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Support\ViewRenderScanner;
use ShieldCI\Tests\Concerns\CreatesTemporaryPaths;

class ViewRenderScannerTest extends TestCase
{
    use CreatesTemporaryPaths;

    private function write(string $dir, string $rel, string $php): string
    {
        $path = $dir.'/'.$rel;
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $php);

        return $path;
    }

    public function test_records_binding_with_type_and_eager_loads(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $controller = $this->write($dir, 'Controller.php', <<<'PHP'
        <?php
        class CityController {
            public function index() {
                $cities = City::with(['airports'])->get();
                return view('admin.cities.index', compact('cities'));
            }
        }
        PHP);

        $registry = (new ViewRenderScanner(new AstParser))->scan([$controller], $dir.'/resources/views');
        $viewFile = $dir.'/resources/views/admin/cities/index.blade.php';
        $resolved = $registry->resolve($viewFile);

        $this->assertNotNull($resolved);
        $this->assertSame('Collection<City>', $resolved['cities']['type']);
        $this->assertEqualsCanonicalizing(['airports'], $resolved['cities']['eagerLoads']);
        $this->assertSame('CityController::index', $resolved['cities']['source']);
    }

    public function test_with_chain_form_is_recognized(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $controller = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function show() {
                $city = City::find(1);
                return view('cities.show')->with('city', $city);
            }
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$controller], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/cities/show.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('City', $resolved['city']['type']);
    }

    public function test_with_chain_binding_to_a_non_variable_has_no_type(): void
    {
        // A literal is neither a typed variable nor a model query, so the binding records
        // no type — which makes the merge policy drop it rather than guess.
        $dir = $this->uniqueTempPath('vrs_');
        $controller = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function show() {
                return view('cities.show')->with('total', 5);
            }
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$controller], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/cities/show.blade.php');

        $this->assertNotNull($resolved);
        $this->assertArrayNotHasKey('total', $resolved);
    }

    public function test_dynamic_view_name_is_skipped(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $controller = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C { public function x() { $t = 'a.b'; return view($t, ['u' => $u]); } }
        PHP);

        $registry = (new ViewRenderScanner(new AstParser))->scan([$controller], $dir.'/resources/views');
        $this->assertNull($registry->resolve($dir.'/resources/views/a/b.blade.php'));
    }

    public function test_file_the_parser_returns_no_ast_for_is_skipped_without_error(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $empty = $this->write($dir, 'Empty.php', "<?php\n");

        $registry = (new ViewRenderScanner(new AstParser))->scan([$empty], $dir.'/resources/views');

        $this->assertNull($registry->resolve($dir.'/resources/views/anything.blade.php'));
    }

    public function test_view_call_inside_top_level_function_uses_file_basename_as_source(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'helpers.php', <<<'PHP'
        <?php
        function renderCity() {
            $city = City::find(1);
            return view('cities.show', ['city' => $city]);
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/cities/show.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('City', $resolved['city']['type']);
        $this->assertSame('helpers.php', $resolved['city']['source']);
    }

    public function test_view_call_with_no_arguments_is_skipped(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function x() {
                return view();
            }
        }
        PHP);

        $registry = (new ViewRenderScanner(new AstParser))->scan([$file], $dir.'/resources/views');

        $this->assertNull($registry->resolve($dir.'/resources/views/anything.blade.php'));
    }

    public function test_doubly_chained_with_calls_are_both_recorded(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function x() {
                $a = City::find(1);
                $b = Airport::find(2);
                return view('v')->with('a', $a)->with('b', $b);
            }
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/v.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('City', $resolved['a']['type']);
        $this->assertSame('Airport', $resolved['b']['type']);
    }

    public function test_array_literal_second_argument_records_bindings(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function index() {
                $cities = City::all();
                $k = 'dynamic';
                return view('cities.index', [
                    'cities' => $cities,
                    'count' => 5,
                    $k => 'ignored',
                ]);
            }
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/cities/index.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('Collection<City>', $resolved['cities']['type']);
        // 'count' has a value that is not a model query (an int literal): a binding is
        // recorded with a null type, which the registry then drops as unanalyzable
        // (ViewBindingRegistry::resolve() only surfaces variables every render site agrees
        // have a known type).
        $this->assertArrayNotHasKey('count', $resolved);
        // $k is a dynamic (non-string) array key: skipped entirely, never becomes a binding.
        $this->assertArrayNotHasKey('dynamic', $resolved);
    }

    public function test_second_argument_that_is_neither_array_nor_compact_yields_no_bindings(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function x() {
                $data = ['a' => 1];
                return view('v', $data);
            }
        }
        PHP);

        $registry = (new ViewRenderScanner(new AstParser))->scan([$file], $dir.'/resources/views');

        $this->assertNull($registry->resolve($dir.'/resources/views/v.blade.php'));
    }

    public function test_with_array_form_records_binding(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function x() {
                $cities = City::all();
                return view('cities.index')->with(['cities' => $cities]);
            }
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/cities/index.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('Collection<City>', $resolved['cities']['type']);
    }

    public function test_with_call_with_unrecognized_arity_yields_no_bindings(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function x() {
                return view('v')->with();
            }
        }
        PHP);

        $registry = (new ViewRenderScanner(new AstParser))->scan([$file], $dir.'/resources/views');

        $this->assertNull($registry->resolve($dir.'/resources/views/v.blade.php'));
    }

    public function test_view_call_inside_a_top_level_route_closure_is_recorded(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'web.php', <<<'PHP'
        <?php
        Route::get('/shelves', function () {
            $shelves = Shelf::with('books')->get();
            return view('shelves.index', compact('shelves'));
        });
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/shelves/index.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('Collection<Shelf>', $resolved['shelves']['type']);
        $this->assertSame(['books'], $resolved['shelves']['eagerLoads']);
        $this->assertSame('web.php', $resolved['shelves']['source']);
    }

    public function test_view_call_inside_an_arrow_function_is_recorded(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'web.php', <<<'PHP'
        <?php
        Route::get('/shelf', fn () => view('shelves.show')->with('shelf', Shelf::findOrFail(1)));
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/shelves/show.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('Shelf', $resolved['shelf']['type']);
    }

    /**
     * A closure nested in a group callback is read as its own scope, and only there: the
     * group callback does not record the nested render site a second time with whatever
     * its sibling closures assigned to the same name.
     */
    public function test_closures_nested_in_a_group_callback_are_separate_scopes(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'web.php', <<<'PHP'
        <?php
        Route::group([], function () {
            Route::get('/a', function () {
                $items = Shelf::all();
                return view('shelves.index', compact('items'));
            });
            Route::get('/b', function () {
                $items = Book::all();
                return view('books.index', compact('items'));
            });
        });
        PHP);

        $registry = (new ViewRenderScanner(new AstParser))->scan([$file], $dir.'/resources/views');

        $shelves = $registry->resolve($dir.'/resources/views/shelves/index.blade.php');
        $books = $registry->resolve($dir.'/resources/views/books/index.blade.php');
        $this->assertNotNull($shelves);
        $this->assertNotNull($books);
        $this->assertSame('Collection<Shelf>', $shelves['items']['type']);
        $this->assertSame('Collection<Book>', $books['items']['type']);
    }

    public function test_inline_model_query_binding_is_typed_with_its_eager_loads(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function index() {
                return view('shelves.index', ['shelves' => Shelf::with(['books.publisher'])->latest()->paginate()]);
            }
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/shelves/index.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('Collection<Shelf>', $resolved['shelves']['type']);
        $this->assertEqualsCanonicalizing(['books', 'books.publisher'], $resolved['shelves']['eagerLoads']);
    }

    /**
     * An anonymous class's method is not part of the closure that declares it, so what the
     * method assigns does not retype the closure's own bindings.
     */
    public function test_anonymous_class_method_inside_a_route_closure_is_not_part_of_its_scope(): void
    {
        $dir = $this->uniqueTempPath('vrs_');
        $file = $this->write($dir, 'web.php', <<<'PHP'
        <?php
        Route::get('/shelves', function () {
            $shelves = Shelf::all();
            $presenter = new class {
                public function render() {
                    $shelves = Book::all();
                }
            };
            return view('shelves.index', compact('shelves'));
        });
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/shelves/index.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('Collection<Shelf>', $resolved['shelves']['type']);
    }
}
